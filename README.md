
## Project 1: SM4的软件实现和优化 


a): 从基本实现出发 优化SM4的软件执行效率，至少应该覆盖T-table、AESNI以及最新的指令集（GFNI、VPROLD等）
b): 基于SM4的实现，做SM4-GCM工作模式的软件优化实现








## Project2：基于数字水印的图片泄露检测（DCT域水印）

编程实现图片水印嵌入和提取（可依托开源项目二次开发），并进行鲁棒性测试，包括不限于翻转、平移、截取、调对比度等

### 2.1 项目简介

本项目旨在通过实现**离散余弦变换 (DCT)** 域的数字水印算法，来演示和验证图片数字水印在版权保护和泄露检测中的应用。我们成功地将一个秘密的二值图片（水印）嵌入到另一张大图片（载体图片）中。更重要的是，我们通过模拟各种常见的图像处理“攻击”，对水印的**鲁棒性**进行了全面测试，评估了在图片被修改后水印是否仍能被成功提取的能力。

本项目基于 **Python 语言**，并充分利用了 `OpenCV` 和 `NumPy` 等强大的图像处理和数值计算库。

### 2.2 核心功能

1. ### **水印嵌入**
    
    - **目标**: 将预设的二值水印（例如公司 Logo 或用户 ID）隐藏到载体图片中。
        
    - **技术实现**:
        
        - 将载体图片转换为 **YCrCb 颜色空间**，因为人眼对亮度 (Y) 通道的变化不如对色度通道敏感，这有助于保持水印的不可感知性。
            
        - 对亮度 (Y) 通道进行 **8x8 分块 DCT 变换**，将图像从空间域转换到频率域。
            
        - 将水印信息（映射为 -1 和 1）嵌入到每个 DCT 块的**中频系数**中。选择中频系数是为了平衡不可感知性与鲁棒性。
            
    - **评估指标**:
        
        - **PSNR (Peak Signal-to-Noise Ratio - 峰值信噪比)**：用于量化含水印图片与原始图片之间的失真程度。PSNR 值越高，表示图像质量损失越小，水印的**不可感知性**越好。
            
2. ### **水印提取**
    
    - **目标**: 从含水印图片（或经过攻击的图片）中准确提取出隐藏的水印信息。
        
    - **技术实现**:
        
        - 对目标图片执行与嵌入时相同的 YCrCb 转换和 **8x8 分块 DCT 变换**。
            
        - 从预设的相同中频系数位置提取 DCT 系数。
            
        - 根据提取出的系数符号（正或负）判决恢复水印比特，然后重构为二值水印图片。
            
    - **评估指标**:
        
        - **NCC (Normalized Correlation Coefficient - 归一化相关系数)**：用于衡量提取出的水印与原始水印的相似度。NCC 值越接近 1，表示提取质量越好，水印的**鲁棒性**越强。
            
3. ### **图像攻击模拟**
    
    - **目标**: 模拟图片在真实传输和使用过程中可能遭遇的各种图像处理操作，以全面测试水印的抵抗能力。
        
    - **攻击类型**:
        
        - **几何攻击**: 翻转（水平/垂直/水平垂直）、平移、旋转、裁剪。
            
        - **信号处理攻击**: 亮度/对比度调整、JPEG 压缩。
            
4. ### **鲁棒性测试**
    
    - **目标**: 系统化地评估水印算法对不同类型和强度的攻击的抵抗能力。
        
    - **流程**: 对经过每种攻击处理的含水印图片进行水印提取，并计算提取出的水印与原始水印的 NCC 值。
        
    - **结果**: 生成可视化图表（柱状图），直观展示不同攻击下的 NCC 表现。

### 2.3 项目结构


```
DigitalWatermarking/
├── src/
│   ├── watermark_embedder.py      # 水印嵌入的核心逻辑（DCT 域实现）
│   ├── watermark_extractor.py     # 水印提取的核心逻辑（DCT 域实现）
│   ├── image_attacks.py           # 模拟各种图像处理攻击
│   └── utils.py                   # 辅助函数：图片读写、PSNR/NCC 计算等
│
├── data/
│   ├── original_images/           # 存放原始载体图片（例如 lenna.jpg）
│   └── watermarks/                # 存放原始水印图片（例如 my_watermark.png, generate_watermark.py）
│
├── results/                       # 实验结果输出目录
│   ├── watermarked_images/        # 嵌入水印后的图片
│   ├── attacked_images/           # 经过各种攻击后的图片
│   ├── extracted_watermarks/      # 从攻击图片中提取出的水印
│   └── performance_reports/       # 性能报告和图表（例如鲁棒性柱状图）
│
├── main.py                        # 项目主入口，协调整个实验流程
└── README.md                      # 项目说明文件 (当前文件)
```

### 2.4 环境准备与运行

#### 2.4.1 **环境依赖**

确保你的系统已安装 **Python 3.8 或更高版本**。然后，通过 `pip` 安装以下必要的 Python 库：

```
pip install opencv-python numpy matplotlib pillow
```

#### 2.4.2 **数据准备**

- **载体图片**: 将你选择的原始载体图片（推荐 `fruits.png`）放入 `data/original_images/` 目录。
    
- **水印图片**:
    - 运行 `data/watermarks/generate_watermark.py` 脚本来自动生成一个示例水印：
        ```
        cd data/watermarks/
        python generate_watermark.py
        ```
        

#### 2.4.3 **运行项目**

打开命令行终端，导航到项目的**根目录** (`DigitalWatermarking/`，即 `main.py` 所在的目录)，然后执行以下命令：

```
python main.py
```

程序将自动执行完整的实验流程，包括：
1. 加载原始图片和水印。
2. 嵌入水印并保存含水印图片。
3. 在无攻击情况下进行水印提取，作为性能基准。
4. 对含水印图片应用一系列预设的图像攻击，并保存攻击后的图片。
5. 从每张攻击后的图片中提取水印，并计算 NCC 值。
6. 生成并显示鲁棒性测试结果的柱状图，同时将图表保存到 `results/performance_reports/robustness_plot.png`。


### 2.5 实验结果与分析

以下是本次实验的关键结果和我的分析。

#### 2.5.1 **水印不可感知性 (PSNR)**

在我的实验中，当水印嵌入强度 `EMBED_ALPHA` 设置为 **[3.0]** 时，原始图片与含水印图片之间的 PSNR 值为 **[35.99]** dB。

- **分析**: 这个 PSNR 值表明水印的不可感知性表现 **[一般]**。通常，PSNR 高于 35dB 被认为是人眼难以察觉的。您可以手动对比 `data/original_images/fruits.jpg` 和 `results/watermarked_images/fruits_watermarked.png` 来进行视觉验证。如果肉眼能明显看到水印痕迹，建议适当降低 `EMBED_ALPHA`。
    

### 2.5.2 **水印鲁棒性 (NCC)**

下表展示了不同攻击类型下，提取出的水印与原始水印的归一化相关系数 (NCC) 值。NCC 越接近 1，表示提取质量越好，水印在遭受该攻击后仍然保持完整性。

|攻击类型|NCC 值|
|---|---|
|**无攻击 (基准)**|0.27|
|水平翻转 (Flip Horizontal)|0.29|
|垂直翻转 (Flip Vertical)|0.21|
|水平垂直翻转 (Flip HV)|0.23|
|平移 (+20, +0)|0.31|
|平移 (+0, +20)|0.33|
|平移 (+20, +20)|0.33|
|旋转 (5 度)|0.22|
|旋转 (15 度)|0.24|
|**裁剪 (并缩放回原尺寸)**|0.23|
|亮度调整 (+30)|0.24|
|亮度调整 (-30)|0.27|
|对比度调整 (alpha=1.2)|0.26|
|对比度调整 (alpha=0.8)|0.27|
|JPEG 压缩 (质量 90)|0.16|
|JPEG 压缩 (质量 75)|0.12|
|JPEG 压缩 (质量 50)|0.10|
|JPEG 压缩 (质量 25)|0.09|


---

**详细分析与讨论**:

- **对几何攻击的鲁棒性**:
    - **翻转和简单的平移**（在不裁剪图片边界的情况下）对基于 DCT 的水印影响相对较小，通常 NCC 值会保持在较高水平。这是因为这些操作通常不会剧烈改变图片像素的局部频率分布。
    - **旋转**对 DCT 水印的鲁棒性表现非常差，NCC 值会显著下降。旋转会打乱 DCT 块的对齐，导致频率域特征的破坏。NCC 值分别为 0.22 (5度) 和 0.24 (15度)。与翻转和平移类似，旋转也严重影响了水印的提取，这证实了 DCT 水印对旋转的低鲁棒性。
    - **裁剪**对分块 DCT 水印是**毁灭性的**。由于裁剪会改变图片尺寸和局部内容，使得提取时无法正确分块和定位水印。即使我们尝试将裁剪后的图片缩放回原始尺寸以进行提取，这种操作本身也引入了额外的失真，导致 NCC 值通常非常低，甚至接近于 0。这明确表明简单的 DCT 水印算法不适用于对抗裁剪攻击。NCC 值为 0.23。这与预期一致，裁剪对分块 DCT 水印是毁灭性的，因为它彻底破坏了图片的网格结构，导致水印提取极度困难。
    
- **对信号处理攻击的鲁棒性**:
    - **亮度/对比度调整**：NCC 值在 0.24 到 0.27 之间，变化不大。这表明该 DCT 水印对图片亮度和对比度的改变具有一定的抵抗力。
    - **JPEG 压缩**：NCC 值随着压缩质量的降低而急剧下降。从质量 90 的 0.16 一直降到质量 25 的 0.09。这表明尽管 DCT 水印对 JPEG 压缩通常有较好的鲁棒性，但在你当前参数设置下，随着压缩强度的增加，水印信息损失非常严重。



### 2.5.3 **结论**

通过本次实验，成功实现并验证了一个基于 DCT 域的数字水印嵌入和提取系统。实验结果表明，在当前的参数设置下，该水印算法的鲁棒性普遍较低，所有测试攻击下的 NCC 值均在 0.09 到 0.33 之间，这说明水印很容易被各种图像处理操作破坏。其中，JPEG 压缩和几何攻击（特别是裁剪和旋转）对水印的影响尤为显著。

为了提高水印的鲁棒性，需要重点优化水印的嵌入强度（EMBED_ALPHA）以及考虑更复杂的嵌入策略或更鲁棒的水印算法。


## Project3：用circom实现poseidon2哈希算法的电路

