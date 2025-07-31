import os
import cv2
import numpy as np
import matplotlib.pyplot as plt
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.watermark_embedder import DCTWatermarkEmbedder
from src.watermark_extractor import DCTWatermarkExtractor
from src.image_attacks import ImageAttacker
from src.utils import load_image, save_image, calculate_psnr, calculate_ncc, display_image

# --- 配置文件 ---
ORIGINAL_IMAGE_PATH = 'data/original_images/fruits.png'
WATERMARK_IMAGE_PATH = 'data/watermarks/my_watermark.png'
WATERMARKED_IMAGE_SAVE_PATH = 'results/watermarked_images/fruits_watermarked.png'
ATTACKED_IMAGES_DIR = 'results/attacked_images/'
EXTRACTED_WATERMARKS_DIR = 'results/extracted_watermarks/'

WATERMARK_SIZE = (32, 32)  # 原始水印尺寸，必须和生成水印时一致
EMBED_ALPHA = 5.0  # 水印嵌入强度，需要反复试验找到最佳值


def main():
    # --- 1. 初始化模块 ---
    embedder = DCTWatermarkEmbedder(alpha=EMBED_ALPHA)
    extractor = DCTWatermarkExtractor(watermark_size=WATERMARK_SIZE)
    attacker = ImageAttacker()

    # --- 2. 加载原始载体图片和原始水印 ---
    original_image = load_image(ORIGINAL_IMAGE_PATH, cv2.IMREAD_COLOR)
    original_watermark = load_image(WATERMARK_IMAGE_PATH, cv2.IMREAD_GRAYSCALE)

    if original_image is None or original_watermark is None:
        print("错误: 无法加载原始图片或水印，请检查路径。")
        return

    # 确保原始水印是二值图片
    if not np.all((original_watermark == 0) | (original_watermark == 255)):
        print("警告: 原始水印图片不是纯粹的二值图片，尝试转换为二值。")
        original_watermark = cv2.threshold(original_watermark, 127, 255, cv2.THRESH_BINARY)[1]

    # --- 3. 水印嵌入 ---
    print("\n--- 阶段：水印嵌入 ---")
    watermarked_image = embedder.embed_watermark(
        ORIGINAL_IMAGE_PATH,
        WATERMARK_IMAGE_PATH,
        WATERMARKED_IMAGE_SAVE_PATH
    )

    if watermarked_image is None:
        print("水印嵌入失败，程序退出。")
        return

    psnr_val = calculate_psnr(original_image, watermarked_image)
    print(f"原始图片与含水印图片之间的 PSNR: {psnr_val:.2f} dB")
    # display_image(original_image, "原始图片")
    # display_image(watermarked_image, "含水印图片")

    # --- 4. 初始水印提取 (无攻击) ---
    print("\n--- 阶段：初始水印提取 (无攻击) ---")
    extracted_wm_no_attack_path = os.path.join(EXTRACTED_WATERMARKS_DIR, "extracted_wm_no_attack.png")
    extracted_wm_no_attack = extractor.extract_watermark(
        WATERMARKED_IMAGE_SAVE_PATH,
        extracted_wm_no_attack_path
    )

    if extracted_wm_no_attack is not None:
        ncc_no_attack = calculate_ncc(original_watermark, extracted_wm_no_attack)
        print(f"无攻击下提取水印的 NCC: {ncc_no_attack:.2f}")
        # display_image(extracted_wm_no_attack, "无攻击下提取的水印")
    else:
        print("无攻击下水印提取失败。")
        return

    # --- 5. 鲁棒性测试 ---
    print("\n--- 阶段：鲁棒性测试 ---")
    attack_results = []  # 存储每次攻击的名称和 NCC 值

    # 使用 watermarked_image 作为基准，每次攻击都从这个图片开始
    base_attack_path = WATERMARKED_IMAGE_SAVE_PATH  # 攻击函数的 output_path 命名时使用这个路径

    # --- 5.1 几何攻击 ---
    print("\n--- 几何攻击测试 ---")
    # 翻转
    print("测试翻转...")
    for flip_code, name in [(0, "vertical_flip"), (1, "horizontal_flip"), (-1, "hv_flip")]:
        attacked_img = attacker.flip(watermarked_image, flip_code, base_attack_path)
        extracted_wm_path = os.path.join(EXTRACTED_WATERMARKS_DIR, f"extracted_wm_{name}.png")
        extracted_wm = extractor.extract_watermark(attacker._get_output_path(base_attack_path, "flip", str(flip_code)),
                                                   extracted_wm_path)
        if extracted_wm is not None:
            ncc = calculate_ncc(original_watermark, extracted_wm)
            attack_results.append((f"Flip ({name})", ncc))
            print(f"  - {name}: NCC = {ncc:.2f}")
        else:
            print(f"  - {name}: 提取失败")

    # 平移 (注意：平移后图片尺寸不变，但内容移动，可能导致边缘信息丢失)
    print("测试平移...")
    for tx, ty in [(20, 0), (0, 20), (20, 20)]:
        attacked_img = attacker.translate(watermarked_image, tx, ty, base_attack_path)
        extracted_wm_path = os.path.join(EXTRACTED_WATERMARKS_DIR, f"extracted_wm_translate_{tx}_{ty}.png")
        extracted_wm = extractor.extract_watermark(
            attacker._get_output_path(base_attack_path, "translate", f"{tx}_{ty}"), extracted_wm_path)
        if extracted_wm is not None:
            ncc = calculate_ncc(original_watermark, extracted_wm)
            attack_results.append((f"Translate ({tx},{ty})", ncc))
            print(f"  - Translate ({tx},{ty}): NCC = {ncc:.2f}")
        else:
            print(f"  - Translate ({tx},{ty}): 提取失败")

    # 旋转 (注意：旋转后图片尺寸不变，但内容旋转，边缘会变为黑色，非常影响分块DCT)
    print("测试旋转...")
    for angle in [5, 15]:  # 角度越大，水印越难提取
        attacked_img = attacker.rotate(watermarked_image, angle, base_attack_path)
        extracted_wm_path = os.path.join(EXTRACTED_WATERMARKS_DIR, f"extracted_wm_rotate_{angle}.png")
        extracted_wm = extractor.extract_watermark(attacker._get_output_path(base_attack_path, "rotate", str(angle)),
                                                   extracted_wm_path)
        if extracted_wm is not None:
            ncc = calculate_ncc(original_watermark, extracted_wm)
            attack_results.append((f"Rotate ({angle}deg)", ncc))
            print(f"  - Rotate ({angle}deg): NCC = {ncc:.2f}")
        else:
            print(f"  - Rotate ({angle}deg): 提取失败")

    # 裁剪 (这对于分块DCT是**非常大的挑战**，通常会失效)
    print("测试裁剪...")
    rows, cols = watermarked_image.shape[:2]
    # 裁剪中间区域，例如裁剪掉 10% 的边缘
    crop_border_px = int(min(rows, cols) * 0.1)
    # 计算裁剪区域
    crop_x = crop_border_px
    crop_y = crop_border_px
    crop_w = cols - 2 * crop_border_px
    crop_h = rows - 2 * crop_border_px

    if crop_w > 0 and crop_h > 0:  # 确保裁剪区域有效
        attacked_img = attacker.crop(watermarked_image, crop_x, crop_y, crop_w, crop_h, base_attack_path)
        # 注意：裁剪后的图片尺寸变化了，直接用extractor提取会失败，
        # 因为extractor需要知道原始水印的相对位置和大小
        # 对于这种攻击，简单的DCT水印基本失效。这里我们为了演示流程，还是尝试提取，但结果会很差。
        extracted_wm_path = os.path.join(EXTRACTED_WATERMARKS_DIR,
                                         f"extracted_wm_crop_{crop_x}_{crop_y}_{crop_w}_{crop_h}.png")

        # 针对裁剪，简单的方案是，将裁剪后的图片**缩放回原始尺寸**再提取
        # 但这种操作本身会引入失真，且不总是有效。
        # 更鲁棒的裁剪攻击防御通常需要更复杂的算法，比如基于特征点等。
        # 这里我们直接尝试，预期NCC会很低。
        # 实际应用中，如果裁剪导致尺寸变化，需要重新对齐或使用尺度不变水印。

        # 尝试将裁剪后的图像缩放回原始大小 (简单但可能效果不好)
        resized_attacked_img = cv2.resize(attacked_img, (cols, rows))  # 缩放回原始载体图片尺寸
        save_image(resized_attacked_img, os.path.join(ATTACKED_IMAGES_DIR, "lenna_watermarked_crop_resized.png"))

        extracted_wm_from_resized = extractor.extract_watermark(
            os.path.join(ATTACKED_IMAGES_DIR, "lenna_watermarked_crop_resized.png"),
            extracted_wm_path
        )

        if extracted_wm_from_resized is not None:
            ncc = calculate_ncc(original_watermark, extracted_wm_from_resized)
            attack_results.append((f"Crop (then resize)", ncc))
            print(f"  - Crop (then resize): NCC = {ncc:.2f}")
        else:
            print(f"  - Crop (then resize): 提取失败")
    else:
        print("  - 裁剪区域过小或无效，跳过裁剪测试。")

    # --- 5.2 信号处理攻击 ---
    print("\n--- 信号处理攻击测试 ---")
    # 亮度/对比度调整
    print("测试亮度/对比度调整...")
    for alpha_val, beta_val in [(1.2, 0), (0.8, 0), (1.0, 30), (1.0, -30)]:
        attacked_img = attacker.adjust_brightness_contrast(watermarked_image, alpha=alpha_val, beta=beta_val,
                                                           output_path=base_attack_path)
        extracted_wm_path = os.path.join(EXTRACTED_WATERMARKS_DIR,
                                         f"extracted_wm_bright_contrast_a{alpha_val}_b{beta_val}.png")
        extracted_wm = extractor.extract_watermark(
            attacker._get_output_path(base_attack_path, "bright_contrast", f"a{alpha_val}_b{beta_val}"),
            extracted_wm_path)
        if extracted_wm is not None:
            ncc = calculate_ncc(original_watermark, extracted_wm)
            attack_results.append((f"Brightness/Contrast (a{alpha_val}, b{beta_val})", ncc))
            print(f"  - Brightness/Contrast (a{alpha_val}, b{beta_val}): NCC = {ncc:.2f}")
        else:
            print(f"  - Brightness/Contrast (a{alpha_val}, b{beta_val}): 提取失败")

    # JPEG 压缩
    print("测试 JPEG 压缩...")
    for quality in [90, 75, 50, 25]:
        attacked_img_path = attacker.jpeg_compress(watermarked_image, quality, base_attack_path)
        if attacked_img_path is None:
            print(f"  - JPEG 压缩质量 {quality}: 攻击失败")
            continue

        extracted_wm_path = os.path.join(EXTRACTED_WATERMARKS_DIR, f"extracted_wm_jpeg{quality}.png")
        extracted_wm = extractor.extract_watermark(attacked_img_path, extracted_wm_path)

        if extracted_wm is not None:
            ncc = calculate_ncc(original_watermark, extracted_wm)
            attack_results.append((f"JPEG Q{quality}", ncc))
            print(f"  - JPEG Q{quality}: NCC = {ncc:.2f}")
        else:
            print(f"  - JPEG Q{quality}: 提取失败")

    # --- 6. 结果可视化 ---
    print("\n--- 结果可视化 ---")
    attack_names = [res[0] for res in attack_results]
    ncc_values = [res[1] for res in attack_results]

    plt.figure(figsize=(12, 7))
    plt.bar(attack_names, ncc_values, color='skyblue')
    plt.xlabel('攻击类型')
    plt.ylabel('NCC (归一化相关系数)')
    plt.title('数字水印鲁棒性测试结果')
    plt.ylim(0, 1.1)  # NCC 范围 0 到 1
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    # 保存图表
    plt.savefig('results/performance_reports/robustness_plot.png')
    plt.show()

    print("\n鲁棒性测试完成。请查看 'results/' 目录下的图片和图表。")


if __name__ == "__main__":
    # 确保输出目录存在
    os.makedirs(ATTACKED_IMAGES_DIR, exist_ok=True)
    os.makedirs(EXTRACTED_WATERMARKS_DIR, exist_ok=True)
    os.makedirs('results/performance_reports/', exist_ok=True)  # 确保报告目录也存在

    main()