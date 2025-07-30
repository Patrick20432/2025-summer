import cv2
import numpy as np
from src.utils import load_image, save_image, convert_to_grayscale, resize_image, calculate_ncc, display_image


class DCTWatermarkExtractor:
    def __init__(self, watermark_size=(32, 32)):
        """
        DCT 数字水印提取器初始化。
        Args:
            watermark_size (tuple): 原始水印的尺寸 (宽度, 高度)，提取时需要知道。
        """
        self.watermark_size = watermark_size

    def _block_dct(self, channel, block_size=8):
        """对图像通道进行分块 DCT 变换。与嵌入器中的相同。"""
        h, w = channel.shape
        pad_h, pad_w = 0, 0
        if h % block_size != 0:
            pad_h = block_size - (h % block_size)
        if w % block_size != 0:
            pad_w = block_size - (w % block_size)

        padded_channel = np.pad(channel, ((0, pad_h), (0, pad_w)), 'constant', constant_values=0)

        blocks_dct = []
        for i in range(0, padded_channel.shape[0], block_size):
            row_blocks = []
            for j in range(0, padded_channel.shape[1], block_size):
                block = padded_channel[i:i + block_size, j:j + block_size]
                block_float = np.float32(block)
                dct_block = cv2.dct(block_float)
                row_blocks.append(dct_block)
            blocks_dct.append(row_blocks)
        return blocks_dct

    def extract_watermark(self, watermarked_image_path, extracted_watermark_output_path):
        """
        从含水印图片中提取水印。
        Args:
            watermarked_image_path (str): 含水印图片路径 (或经过攻击的图片路径)。
            extracted_watermark_output_path (str): 提取出的水印图片保存路径。
        Returns:
            np.array: 提取出的水印数据 (二值图片)。
        """
        # 1. 加载含水印图片
        image = load_image(watermarked_image_path, cv2.IMREAD_COLOR)
        if image is None:
            print("错误：无法加载含水印图片，请检查路径。")
            return None

        # 2. 转换为 YCrCb 颜色空间并提取 Y 通道
        ycbcr_image = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb)
        Y_channel = ycbcr_image[:, :, 0]

        # 3. 对 Y 通道进行分块 DCT
        blocks_dct_Y = self._block_dct(Y_channel, block_size=8)

        # 4. 提取水印位
        extracted_watermark_flat = []
        embed_row, embed_col = 4, 4  # 和嵌入时一样的中频系数位置

        # 计算理论上可以提取的比特数
        # 每个8x8块嵌入一个比特，所以理论可嵌入比特数是 (图片宽/8) * (图片高/8)
        num_blocks_h = len(blocks_dct_Y)
        num_blocks_w = len(blocks_dct_Y[0]) if num_blocks_h > 0 else 0
        max_extractable_bits = num_blocks_h * num_blocks_w

        # 我们提取的水印长度应该和我们嵌入的原始水印长度一致
        # 这里的提取是基于事先知道水印尺寸 (self.watermark_size)
        target_watermark_len = self.watermark_size[0] * self.watermark_size[1]

        watermark_idx = 0
        for i in range(num_blocks_h):
            for j in range(num_blocks_w):
                if watermark_idx < target_watermark_len:
                    dct_block = blocks_dct_Y[i][j]

                    # 提取该位置的 DCT 系数
                    coefficient = dct_block[embed_row, embed_col]

                    # 基于系数的符号或阈值判断水印位
                    # 如果系数大于某个阈值（接近原始嵌入的 alpha/2），则认为是 1 (白)
                    # 如果系数小于某个负阈值（接近原始嵌入的 -alpha/2），则认为是 -1 (黑)
                    # 考虑到图像处理和量化误差，我们使用一个简单的判决：
                    # 大于0认为是1，小于等于0认为是-1 (因为原始水印是-1或1)
                    extracted_bit = 1 if coefficient > 0 else -1
                    extracted_watermark_flat.append(extracted_bit)
                    watermark_idx += 1
                else:
                    break
            if watermark_idx >= target_watermark_len:
                break

        # 5. 将提取出的比特序列转换回二值图片格式 (0 或 255)
        # 注意：这里需要确保提取出的比特数和原始水印尺寸匹配
        extracted_watermark_flat = np.array(extracted_watermark_flat)[:target_watermark_len]  # 截断或填充以匹配长度

        # 将 -1 映射回 0 (黑色), 将 1 映射回 255 (白色)
        extracted_watermark_binary = ((extracted_watermark_flat + 1) / 2) * 255
        extracted_watermark_image = extracted_watermark_binary.reshape(self.watermark_size).astype(np.uint8)

        # 6. 保存提取出的水印
        save_image(extracted_watermark_image, extracted_watermark_output_path)

        return extracted_watermark_image


if __name__ == "__main__":
    print("正在测试 watermark_extractor.py 中的功能...")

    extractor = DCTWatermarkExtractor(watermark_size=(32, 32))  # 原始水印是 32x32

    # 1. 从之前嵌入水印的图片中提取
    watermarked_image_path = '../results/watermarked_images/fruits_watermarked.png'
    extracted_wm_output_path = '../results/extracted_watermarks/extracted_wm_from_watermarked.png'

    extracted_watermark = extractor.extract_watermark(watermarked_image_path, extracted_wm_output_path)

    if extracted_watermark is not None:
        # 加载原始水印进行对比
        original_watermark_path = '../data/watermarks/my_watermark.png'
        original_watermark = load_image(original_watermark_path, cv2.IMREAD_GRAYSCALE)

        if original_watermark is not None:
            # 确保原始水印也是二值图
            original_watermark_binary = (original_watermark // 255) * 255

            # 计算 NCC，评估提取质量
            ncc_val = calculate_ncc(original_watermark_binary, extracted_watermark)
            print(f"从含水印图片中提取出的水印与原始水印的 NCC: {ncc_val:.2f}")

            # 显示原始水印和提取出的水印进行对比
            display_image(original_watermark_binary, "原始水印")
            display_image(extracted_watermark, "提取出的水印 (从含水印图片)")
        else:
            print("未能加载原始水印，跳过 NCC 计算和显示。")
    else:
        print("水印提取测试失败。")

    print("watermark_extractor.py 功能测试完成。")