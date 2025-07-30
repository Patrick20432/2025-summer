import cv2
import numpy as np
from src.utils import load_image, save_image, convert_to_grayscale, resize_image, calculate_psnr, display_image


class DCTWatermarkEmbedder:
    def __init__(self, alpha=0.01):
        """
        DCT 数字水印嵌入器初始化。
        Args:
            alpha (float): 水印嵌入强度因子。值越大，水印越明显（可见性差），但鲁棒性越强。
                           需要调整以平衡不可感知性和鲁棒性。
        """
        self.alpha = alpha

    def _block_dct(self, channel, block_size=8):
        """对图像通道进行分块 DCT 变换。"""
        h, w = channel.shape
        # 确保图片尺寸是 block_size 的倍数，不足部分用零填充
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
                dct_block = cv2.dct(block_float)  # 进行 DCT 变换
                row_blocks.append(dct_block)
            blocks_dct.append(row_blocks)
        return blocks_dct, (h, w), (pad_h, pad_w)  # 返回原始尺寸和填充信息

    def _block_idct(self, blocks_dct, original_shape, padding):
        """对分块 DCT 系数进行逆 DCT 变换并重组图像。"""
        block_size = blocks_dct[0][0].shape[0]
        rows = []
        for i, row_blocks in enumerate(blocks_dct):
            row_images = []
            for j, dct_block in enumerate(row_blocks):
                idct_block = cv2.idct(dct_block)  # 进行 IDCT 变换
                idct_block = np.clip(idct_block, 0, 255)  # 将像素值裁剪到 0-255 范围
                row_images.append(idct_block)
            rows.append(np.hstack(row_images))  # 水平拼接
        reconstructed_channel = np.vstack(rows)  # 垂直拼接

        # 移除填充
        h_orig, w_orig = original_shape
        pad_h, pad_w = padding
        reconstructed_channel = reconstructed_channel[:h_orig, :w_orig]

        return np.uint8(reconstructed_channel)  # 转换为 uint8 类型

    def embed_watermark(self, cover_image_path, watermark_image_path, output_path):
        """
        将水印图片嵌入到载体图片中。
        Args:
            cover_image_path (str): 载体图片路径。
            watermark_image_path (str): 水印图片路径 (二值图片)。
            output_path (str): 含水印图片保存路径。
        Returns:
            np.array: 含水印图片数据。
        """
        # 1. 加载图片
        cover_image = load_image(cover_image_path, cv2.IMREAD_COLOR)
        watermark = load_image(watermark_image_path, cv2.IMREAD_GRAYSCALE)

        if cover_image is None or watermark is None:
            print("错误：无法加载图片，请检查路径。")
            return None

        # 1.1 强制二值化
        _, watermark = cv2.threshold(watermark, 127, 255, cv2.THRESH_BINARY)

        # 1.2 归一化：0→-1，255→1
        watermark_binary = (watermark.astype(np.float32) / 255) * 2 - 1  # shape 不变
        watermark_flat = watermark_binary.flatten()
        if not np.all((watermark == 0) | (watermark == 255)):
            print("错误：水印图片不是纯粹的二值图片（只包含0和255）。")
            return None

        # 将水印归一化到 0 和 1 (0 -> -1, 255 -> 1)
        # 这样水印信息可以直接加到DCT系数上，避免对0系数没有影响
        watermark_binary = (watermark // 255) * 2 - 1  # 0->-1, 255->1

        # 2. 调整水印大小以适应载体图片
        # 简单起见，我们选择一个固定的水印区域大小，并确保水印能完全放下
        # 原始载体图片越大，能嵌入的水印信息量越大，鲁棒性越好。
        # 这里我们假设水印尺寸固定为 32x32，并确保载体图片足够大，至少是 8x8 块的倍数
        # 实际中，可以根据载体图片大小动态调整水印区域。

        # 为了简化，我们假设载体图片是正方形，并且其边长是 8 的倍数。
        # 我们可以将水印嵌入到左上角的 (32, 32) 区域，或者根据图片大小调整一个区域。
        # 这里我们简单地将水印调整到 32x32，并假设它会被嵌入到一个 8x8 的块序列中。

        # 最简单的方式，直接调整水印到某个预设的固定尺寸 (例如 32x32)，
        # 然后将这个水印展开成一维序列，依次嵌入到载体图片DCT系数的特定位置
        watermark_flat = watermark_binary.flatten()
        watermark_len = watermark_flat.shape[0]

        # 3. 分离通道，并在亮度通道 (Y通道) 嵌入水印
        # RGB转YCbCr，Y通道代表亮度，对Y通道修改对人眼感知影响较小
        ycbcr_image = cv2.cvtColor(cover_image, cv2.COLOR_BGR2YCrCb)
        Y_channel = ycbcr_image[:, :, 0]  # 提取Y通道

        # 4. 对Y通道进行分块DCT
        # block_dct 函数会处理填充，这里直接传入Y通道
        blocks_dct_Y, original_Y_shape, Y_padding = self._block_dct(Y_channel, block_size=8)

        # 5. 嵌入水印
        # 我们将水印嵌入到每个8x8块的特定中频系数中
        # 比如，每个块只嵌入一个比特，那么需要的水印区域就取决于水印长度
        # 这里，我们遍历DCT块，将水印位嵌入到每个块的 (5, 5) 处 (中频系数)

        watermark_idx = 0
        for i in range(len(blocks_dct_Y)):
            for j in range(len(blocks_dct_Y[i])):
                if watermark_idx < watermark_len:
                    # 获取当前块的DCT系数
                    dct_block = blocks_dct_Y[i][j]

                    # 确定嵌入位置 (例如，中频的 (5, 5) 或 (4, 4) 系数)
                    # 这个位置的选择影响鲁棒性和不可感知性。
                    # 通常选择对视觉影响不大的中频系数。
                    embed_row, embed_col = 4, 4  # 选择一个中频系数

                    # 嵌入水印位：系数 = 系数 + alpha * 水印位
                    # 如果水印位是 1，则系数增加；如果是 -1，则系数减少。
                    # 这样可以避免只对正系数产生影响的问题。
                    dct_block[embed_row, embed_col] += self.alpha * watermark_flat[watermark_idx]

                    # 更新嵌入后的DCT块
                    blocks_dct_Y[i][j] = dct_block
                    watermark_idx += 1
                else:
                    break  # 水印嵌入完毕
            if watermark_idx >= watermark_len:
                break

        print(f"水印嵌入完成。共嵌入 {watermark_idx} 比特。")

        # 6. 对Y通道进行逆DCT，并重构图像
        Y_channel_watermarked = self._block_idct(blocks_dct_Y, original_Y_shape, Y_padding)

        # 7. 将水印后的Y通道与Cb、Cr通道合并，并转换回RGB
        ycbcr_image_watermarked = ycbcr_image.copy()
        ycbcr_image_watermarked[:, :, 0] = Y_channel_watermarked

        watermarked_image_bgr = cv2.cvtColor(ycbcr_image_watermarked, cv2.COLOR_YCrCb2BGR)

        # 8. 保存含水印图片
        save_image(watermarked_image_bgr, output_path)

        return watermarked_image_bgr


if __name__ == "__main__":
    print("正在测试 watermark_embedder.py 中的功能...")

    embedder = DCTWatermarkEmbedder(alpha=5.0)  # 调整 alpha 值，尝试 1.0 到 10.0 之间的值

    cover_path = '../data/original_images/fruits.png'
    watermark_path = '../data/watermarks/my_watermark.png'
    output_watermarked_path = '../results/watermarked_images/fruits_watermarked.png'

    original_image = load_image(cover_path)
    watermarked_image = embedder.embed_watermark(cover_path, watermark_path, output_watermarked_path)

    if original_image is not None and watermarked_image is not None:
        # 计算 PSNR，评估不可感知性
        psnr_val = calculate_psnr(original_image, watermarked_image)
        print(f"原始图片与含水印图片之间的 PSNR: {psnr_val:.2f} dB")

        # 显示原始图片和含水印图片进行对比
        display_image(original_image, "原始图片")
        display_image(watermarked_image, "含水印图片")
    else:
        print("水印嵌入测试失败。")

    print("watermark_embedder.py 功能测试完成。")