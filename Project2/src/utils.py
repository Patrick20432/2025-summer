import cv2
import numpy as np
import os
from PIL import Image

# --- 图像读写函数 ---

def load_image(image_path, color=cv2.IMREAD_COLOR):
    """
    加载图片。
    Args:
        image_path (str): 图片文件路径。
        color (int): 加载模式，cv2.IMREAD_COLOR (彩色), cv2.IMREAD_GRAYSCALE (灰度)。
    Returns:
        np.array: 加载的图片数据 (NumPy 数组)。
    """
    if not os.path.exists(image_path):
        print(f"错误: 文件未找到 - {image_path}")
        return None
    img = cv2.imread(image_path, color)
    if img is None:
        print(f"错误: 无法加载图片 - {image_path}")
    return img

def save_image(image_data, save_path):
    """
    保存图片。
    Args:
        image_data (np.array): 要保存的图片数据。
        save_path (str): 保存路径。
    """
    # 确保保存路径的目录存在
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    cv2.imwrite(save_path, image_data)
    print(f"图片已保存到: {save_path}")

def display_image(image_data, window_name="Image"):
    """
    显示图片 (短暂显示，按任意键关闭)。
    Args:
        image_data (np.array): 要显示的图片数据。
        window_name (str): 窗口名称。
    """
    cv2.imshow(window_name, image_data)
    cv2.waitKey(0) # 等待按键
    cv2.destroyAllWindows()

# --- 图像转换和调整函数 ---

def convert_to_grayscale(image_data):
    """将彩色图片转换为灰度图片。"""
    if len(image_data.shape) == 3 and image_data.shape[2] == 3: # 如果是彩色图片 (BGR)
        return cv2.cvtColor(image_data, cv2.COLOR_BGR2GRAY)
    return image_data # 如果已经是灰度图或单通道图，则直接返回

def resize_image(image_data, target_size):
    """
    调整图片大小。
    Args:
        image_data (np.array): 图片数据。
        target_size (tuple): 目标尺寸 (宽度, 高度)。
    Returns:
        np.array: 调整大小后的图片数据。
    """
    return cv2.resize(image_data, target_size)

# --- 评估指标函数 ---

def calculate_psnr(original_image, watermarked_image):
    """
    计算两张图片之间的峰值信噪比 (PSNR)。用于评估水印的不可感知性。
    值越大，表示失真越小，水印越不可感知。
    Args:
        original_image (np.array): 原始图片。
        watermarked_image (np.array): 含水印图片。
    Returns:
        float: PSNR 值。
    """
    # 确保图片数据类型和维度一致
    if original_image.shape != watermarked_image.shape:
        # 如果维度不一致，尝试调整大小或转换
        # 这里我们假设它们是相同维度的，如果不同，需要先处理
        print("警告: 原始图片和含水印图片维度不一致，无法计算PSNR。")
        return -1

    # 如果是彩色图，转换为灰度图计算PSNR，或者分别计算R,G,B通道再求平均
    # 简单起见，我们这里转换为灰度图
    if len(original_image.shape) == 3:
        original_image = cv2.cvtColor(original_image, cv2.COLOR_BGR2GRAY)
        watermarked_image = cv2.cvtColor(watermarked_image, cv2.COLOR_BGR2GRAY)

    mse = np.mean((original_image - watermarked_image) ** 2)
    if mse == 0:
        return float('inf') # 两张图片完全相同
    max_pixel = 255.0 # 8位图片的像素最大值
    psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
    return psnr

def calculate_ncc(original_watermark, extracted_watermark):
    """
    计算两张二值图片（水印）之间的归一化相关系数 (NCC)。用于评估水印的鲁棒性。
    值越接近 1，表示提取的水印与原始水印越相似。
    Args:
        original_watermark (np.array): 原始水印 (二值图片，0或255)。
        extracted_watermark (np.array): 提取出的水印 (二值图片，0或255)。
    Returns:
        float: NCC 值。
    """
    # 确保水印图片是二值的，并且维度一致
    if original_watermark.shape != extracted_watermark.shape:
        print("警告: 原始水印和提取水印维度不一致，无法计算NCC。")
        return -1

    # 归一化到 0 和 1
    original_watermark_norm = original_watermark / 255.0
    extracted_watermark_norm = extracted_watermark / 255.0

    numerator = np.sum(original_watermark_norm * extracted_watermark_norm)
    denominator = np.sqrt(np.sum(original_watermark_norm**2) * np.sum(extracted_watermark_norm**2))

    if denominator == 0:
        return 0.0 # 避免除以零

    ncc = numerator / denominator
    return ncc

# --- 验证函数 ---

def is_binary_image(image_data):
    """
    检查图片是否是二值图片 (只包含0和255)。
    """
    unique_pixels = np.unique(image_data)
    return all(pixel in [0, 255] for pixel in unique_pixels)


if __name__ == "__main__":
    # --- 简单测试 utils.py 中的函数 ---
    print("正在测试 utils.py 中的函数...")

    # 1. 测试图片加载和保存
    # 假设你已经把 lenna.jpg 放在了 data/original_images/
    test_image_path = '../data/original_images/fruits.png'
    img = load_image(test_image_path)
    if img is not None:
        print(f"成功加载图片: {test_image_path}, 形状: {img.shape}")
        # save_image(img, '../results/test_image_copy.jpg') # 可以取消注释测试保存

        # 2. 测试灰度转换
        gray_img = convert_to_grayscale(img)
        print(f"灰度图形状: {gray_img.shape}")
        # display_image(gray_img, "灰度测试图")

        # 3. 测试图片调整大小
        resized_img = resize_image(img, (256, 256)) # 宽, 高
        print(f"调整大小后的图片形状: {resized_img.shape}")
        # display_image(resized_img, "调整大小测试图")

    # 4. 测试 PSNR
    # 需要两张图片，我们简单复制一张来模拟
    img1 = np.zeros((100, 100), dtype=np.uint8) + 100 # 纯色图片
    img2 = np.zeros((100, 100), dtype=np.uint8) + 105 # 有轻微差异的图片
    psnr_val = calculate_psnr(img1, img2)
    print(f"PSNR (img1 vs img2): {psnr_val:.2f} dB") # 理论值: 20*log10(255/sqrt(5^2)) = 20*log10(255/5) = 20*log10(51)约等于34.15dB

    # 5. 测试 NCC
    # 假设你已经把 my_watermark.png 放在了 data/watermarks/
    watermark_path = '../data/watermarks/my_watermark.png'
    original_wm = load_image(watermark_path, cv2.IMREAD_GRAYSCALE)
    if original_wm is not None:
        # 模拟一个完美提取的水印
        extracted_wm_perfect = original_wm.copy()
        ncc_perfect = calculate_ncc(original_wm, extracted_wm_perfect)
        print(f"NCC (完美提取): {ncc_perfect:.2f}")

        # 模拟一个有错误的提取水印
        extracted_wm_error = original_wm.copy()
        # 随机翻转几个像素来模拟错误
        num_errors = 5
        rows, cols = extracted_wm_error.shape
        for _ in range(num_errors):
            r = np.random.randint(0, rows)
            c = np.random.randint(0, cols)
            extracted_wm_error[r, c] = 255 - extracted_wm_error[r, c] # 翻转像素值
        ncc_error = calculate_ncc(original_wm, extracted_wm_error)
        print(f"NCC (有错误提取): {ncc_error:.2f}")
    else:
        print("未能加载测试水印图片，跳过NCC测试。请确保 'my_watermark.png' 在正确位置。")

    print("utils.py 函数测试完成。")