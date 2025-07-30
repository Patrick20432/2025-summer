import cv2
import numpy as np
import os
from src.utils import save_image, load_image


class ImageAttacker:
    def __init__(self):
        pass

    def _get_output_path(self, base_path, attack_name, param_str=""):
        """生成攻击后图片的保存路径。"""
        # 获取文件名和扩展名
        filename, ext = os.path.splitext(os.path.basename(base_path))
        output_dir = os.path.dirname(base_path)

        # 构建新的文件名
        if param_str:
            new_filename = f"{filename}_{attack_name}_{param_str}{ext}"
        else:
            new_filename = f"{filename}_{attack_name}{ext}"

        return os.path.join(output_dir, new_filename)

    def flip(self, image_data, flip_code, output_path=None):
        """
        图片翻转。
        Args:
            image_data (np.array): 图片数据。
            flip_code (int): 翻转代码 (0: 垂直翻转, 1: 水平翻转, -1: 水平垂直翻转)。
            output_path (str): 保存路径。
        Returns:
            np.array: 翻转后的图片。
        """
        flipped_image = cv2.flip(image_data, flip_code)
        if output_path:
            save_image(flipped_image, self._get_output_path(output_path, "flip", str(flip_code)))
        return flipped_image

    def translate(self, image_data, tx, ty, output_path=None):
        """
        图片平移。
        Args:
            image_data (np.array): 图片数据。
            tx (int): 水平平移像素。
            ty (int): 垂直平移像素。
            output_path (str): 保存路径。
        Returns:
            np.array: 平移后的图片。
        """
        rows, cols = image_data.shape[:2]
        M = np.float32([[1, 0, tx], [0, 1, ty]])  # 2x3 变换矩阵
        translated_image = cv2.warpAffine(image_data, M, (cols, rows))  # warpAffine 保持原图尺寸
        if output_path:
            save_image(translated_image, self._get_output_path(output_path, "translate", f"{tx}_{ty}"))
        return translated_image

    def rotate(self, image_data, angle, output_path=None):
        """
        图片旋转。
        Args:
            image_data (np.array): 图片数据。
            angle (float): 旋转角度 (度)。
            output_path (str): 保存路径。
        Returns:
            np.array: 旋转后的图片。
        """
        rows, cols = image_data.shape[:2]
        M = cv2.getRotationMatrix2D(((cols - 1) / 2.0, (rows - 1) / 2.0), angle, 1)  # 旋转中心在图片中心，缩放因子1
        rotated_image = cv2.warpAffine(image_data, M, (cols, rows))
        if output_path:
            save_image(rotated_image, self._get_output_path(output_path, "rotate", str(angle)))
        return rotated_image

    def crop(self, image_data, x, y, width, height, output_path=None):
        """
        图片裁剪。
        Args:
            image_data (np.array): 图片数据。
            x (int): 裁剪区域左上角x坐标。
            y (int): 裁剪区域左上角y坐标。
            width (int): 裁剪区域宽度。
            height (int): 裁剪区域高度。
            output_path (str): 保存路径。
        Returns:
            np.array: 裁剪后的图片。
        """
        cropped_image = image_data[y:y + height, x:x + width]
        if output_path:
            save_image(cropped_image, self._get_output_path(output_path, "crop", f"{x}_{y}_{width}_{height}"))
        return cropped_image

    def adjust_brightness_contrast(self, image_data, alpha=1.0, beta=0, output_path=None):
        """
        调整图片亮度（beta）和对比度（alpha）。
        new_image = alpha * old_image + beta
        Args:
            image_data (np.array): 图片数据。
            alpha (float): 对比度调整因子 (1.0表示不变)。
            beta (int): 亮度调整值 (0表示不变)。
            output_path (str): 保存路径。
        Returns:
            np.array: 调整后的图片。
        """
        adjusted_image = cv2.convertScaleAbs(image_data, alpha=alpha, beta=beta)
        if output_path:
            save_image(adjusted_image, self._get_output_path(output_path, "bright_contrast", f"a{alpha}_b{beta}"))
        return adjusted_image

    def jpeg_compress(self, image_data, quality, output_path=None):
        """
        JPEG 压缩图片。
        Args:
            image_data (np.array): 图片数据。
            quality (int): JPEG 压缩质量 (0-100, 100为最高质量)。
            output_path (str): 保存路径。
        Returns:
            np.array: 压缩后的图片。
        """
        # 注意：cv2.imwrite 会根据文件扩展名自动处理压缩
        # 所以这里我们只改变 output_path 的扩展名为 .jpg
        if output_path:
            # 确保保存路径是 .jpg
            jpeg_output_path = os.path.splitext(output_path)[0] + f"_jpeg{quality}.jpg"
            cv2.imwrite(jpeg_output_path, image_data, [cv2.IMWRITE_JPEG_QUALITY, quality])
            print(f"JPEG 压缩图片已保存到: {jpeg_output_path}")
            # 重新加载压缩后的图片，因为 imwrite 保存后可能无法直接使用原始数据进行后续处理
            # 尤其是有损压缩
            return load_image(jpeg_output_path)
        else:
            # 如果没有输出路径，则不能直接进行 JPEG 压缩
            # 因为 JPEG 压缩是有损的，需要保存和重新加载才能体现效果
            print("警告: JPEG压缩需要指定 output_path 来保存并重新加载以体现压缩效果。")
            return image_data


if __name__ == "__main__":
    print("正在测试 image_attacks.py 中的功能...")

    attacker = ImageAttacker()

    test_image_path = '../results/watermarked_images/fruits_watermarked.png'
    test_image = load_image(test_image_path)

    if test_image is None:
        print("错误: 未找到测试图片。请确保 'fruits_watermarked.png' 存在。")
    else:
        # 关键：给出一个带扩展名的基准文件名
        output_base_path = '../results/attacked_images/fruits_watermarked.png'

        # 1. 翻转
        flipped_h = attacker.flip(test_image, 1, output_path=output_base_path)
        flipped_v = attacker.flip(test_image, 0, output_path=output_base_path)

        # 2. 平移
        translated_img = attacker.translate(test_image, 50, 30,
                                            output_path=output_base_path)

        # 3. 旋转
        rotated_img = attacker.rotate(test_image, 15,
                                      output_path=output_base_path)

        # 4. 裁剪
        rows, cols = test_image.shape[:2]
        crop_x = int(cols * 0.2)
        crop_y = int(rows * 0.2)
        crop_w = int(cols * 0.6)
        crop_h = int(rows * 0.6)
        cropped_img = attacker.crop(test_image, crop_x, crop_y, crop_w, crop_h,
                                    output_path=output_base_path)

        # 5. 亮度/对比度
        adjusted_img_bright = attacker.adjust_brightness_contrast(
            test_image, beta=50, output_path=output_base_path)
        adjusted_img_contrast = attacker.adjust_brightness_contrast(
            test_image, alpha=1.5, output_path=output_base_path)

        # 6. JPEG 压缩
        jpeg_compressed_img = attacker.jpeg_compress(
            test_image, 50, output_path=output_base_path)

        print("image_attacks.py 功能测试完成。请检查 'results/attacked_images/' 目录。")