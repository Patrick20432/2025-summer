import numpy as np
from PIL import Image, ImageDraw, ImageFont

def generate_simple_watermark(size=(32, 32), text="A"):
    """生成一个简单的二值水印图片"""
    # 创建全黑 8-bit 灰度图像
    img_array = np.zeros(size, dtype=np.uint8)
    img = Image.fromarray(img_array, mode="L")

    # 准备绘图
    draw = ImageDraw.Draw(img)

    # 加载字体
    try:
        font = ImageFont.truetype("arial.ttf", 20)
    except IOError:
        font = ImageFont.load_default()
        print("Warning: Arial font not found, using default font.")

    # 计算文本尺寸与居中位置（兼容 Pillow 8–10+）
    bbox = draw.textbbox((0, 0), text, font=font)  # (left, top, right, bottom)
    text_width  = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (size[0] - text_width)  // 2
    y = (size[1] - text_height) // 2

    # 绘制白色文本
    draw.text((x, y), text, fill=255, font=font)

    return img

if __name__ == "__main__":
    watermark_image = generate_simple_watermark(size=(32, 32), text="W")
    watermark_image_path = 'my_watermark.png'
    watermark_image.save(watermark_image_path)
    print(f"水印图片已生成并保存到: {watermark_image_path}")
    watermark_image.show()