import os
import subprocess
import wave
import numpy as np
import struct
from scipy.io import wavfile
from scipy.signal import resample

# ==================== 配置参数 ====================
TARGET_SAMPLE_RATE = 8000 * 2  # 16000 Hz (第一步转换的目标，也是最终头文件的采样率)
VOLUME_GAIN = "4dB"
INPUT_DIR = "."                 # 原始WAV文件所在目录
TEMP_DIR = "converted_wav-3"   # 临时转换目录（16kHz）
FINAL_DIR = "final_wav-12bit"  # 最终12位WAV目录
HEADER_DIR = "audio_headers"   # C头文件输出目录


# ==================== 第一步：批量转换采样率和音量 ====================
def convert_sample_rate_and_volume():
    """使用ffmpeg批量转换采样率和音量"""
    os.makedirs(TEMP_DIR, exist_ok=True)
    
    wav_files = [f for f in os.listdir(INPUT_DIR) 
                 if f.lower().endswith(".wav")]
    
    if not wav_files:
        print(f"警告：在 {INPUT_DIR} 中没有找到WAV文件")
        return False
    
    for filename in wav_files:
        input_path = os.path.join(INPUT_DIR, filename)
        output_path = os.path.join(TEMP_DIR, filename)
        
        cmd = [
            "ffmpeg", "-y",
            "-i", input_path,
            "-filter:a", f"volume={VOLUME_GAIN}",
            "-ar", str(TARGET_SAMPLE_RATE),
            output_path
        ]
        
        print(f"正在转换: {filename}")
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print(f"✓ 采样率转换完成！保存于：{TEMP_DIR}\n")
    return True


# ==================== 第二步：查看WAV文件信息 ====================
def analyze_wav_files():
    """分析WAV文件的详细信息"""
    os.chdir(TEMP_DIR)
    wav_files = [f for f in os.listdir() if f.endswith(".wav")]
    
    if not wav_files:
        print("警告：临时目录中没有WAV文件")
        os.chdir(INPUT_DIR)
        return
    
    print("=" * 60)
    print("WAV文件信息分析")
    print("=" * 60)
    
    for filename in wav_files:
        with wave.open(filename, 'rb') as wav_file:
            channels = wav_file.getnchannels()
            sample_rate = wav_file.getframerate()
            sample_width = wav_file.getsampwidth()
            bit_depth = sample_width * 8
            n_frames = wav_file.getnframes()
            
            print(f"\n文件: {filename}")
            print(f"  采样率: {sample_rate} Hz")
            print(f"  位深度: {bit_depth}-bit")
            print(f"  声道数: {channels}")
            print(f"  帧数: {n_frames}")
            
            # 读取并分析PCM数据
            raw_data = wav_file.readframes(n_frames)
            fmt_char = {1: 'b', 2: 'h'}[sample_width]
            fmt = f"<{n_frames * channels}{fmt_char}"
            samples = struct.unpack(fmt, raw_data)
            
            # 如果是多声道，转换为单声道
            if channels > 1:
                samples = [(samples[i] + samples[i+1]) // 2 
                          for i in range(0, len(samples), channels)]
            
            print(f"  音频范围: Min = {min(samples)}, Max = {max(samples)}")
    
    print("\n" + "=" * 60)
    os.chdir(INPUT_DIR)


# ==================== 第三步：转换为12位深度WAV ====================
def convert_to_12bit_wav():
    """将16位WAV转换为12位无符号格式并保存为WAV文件"""
    os.makedirs(FINAL_DIR, exist_ok=True)
    
    wav_files = [f for f in os.listdir(TEMP_DIR) if f.endswith(".wav")]
    
    if not wav_files:
        print("警告：临时目录中没有WAV文件")
        return
    
    print("开始转换为12位深度WAV...")
    print("=" * 60)
    
    for filename in wav_files:
        input_path = os.path.join(TEMP_DIR, filename)
        output_path = os.path.join(FINAL_DIR, filename)
        
        with wave.open(input_path, 'rb') as wav_in:
            # 获取WAV文件参数
            params = wav_in.getparams()
            num_channels, sample_width, framerate, num_frames = params[:4]
            
            # 读取16位PCM数据
            audio_data = np.frombuffer(wav_in.readframes(num_frames), dtype=np.int16)
            
            # 转换16位有符号(-32768~32767) 到 12位无符号(0~4095)
            audio_data_12bit = ((audio_data + 32768) * 4095 / 65535).astype(np.uint16)
            
            print(f"\n{filename}:")
            print(f"  转换前范围: {audio_data.min()} ~ {audio_data.max()}")
            print(f"  转换后范围: {audio_data_12bit.min()} ~ {audio_data_12bit.max()}")
            
            # 保存为12位WAV
            with wave.open(output_path, 'wb') as wav_out:
                wav_out.setparams((num_channels, 2, framerate, num_frames, 
                                  'NONE', 'not compressed'))
                wav_out.writeframes(audio_data_12bit.tobytes())
    
    print("\n" + "=" * 60)
    print(f"✓ 12位WAV转换完成！保存于：{FINAL_DIR}")


# ==================== 第四步：生成C头文件（16kHz） ====================
def generate_c_header(input_file, output_header, target_sample_rate=TARGET_SAMPLE_RATE):
    """
    将WAV文件转换为指定采样率和位深，并生成C头文件
    
    :param input_file: 输入WAV文件路径
    :param output_header: 输出头文件路径
    :param target_sample_rate: 目标采样率（默认16000Hz）
    """
    try:
        # 读取WAV文件
        sample_rate, data = wavfile.read(input_file)
    except Exception as e:
        print(f"  读取WAV文件失败: {e}")
        return False

    # 如果是浮点数据，先转换为整数
    if np.issubdtype(data.dtype, np.floating):
        data = (data * 32767).astype(np.int16)

    # 如果音频是立体声，转换为单声道
    if data.ndim > 1:
        data = data.mean(axis=1).astype(np.int16)

    # 重采样到目标采样率（如果需要）
    if sample_rate != target_sample_rate:
        print(f"  重采样: {sample_rate}Hz -> {target_sample_rate}Hz")
        num_samples = int(len(data) * target_sample_rate / sample_rate)
        data = resample(data, num_samples)
        data = np.clip(data, -32768, 32767).astype(np.int16)

    # 显示音频范围
    data_min = data.min()
    data_max = data.max()
    print(f"  音频范围: {data_min} ~ {data_max}")
    print(f"  数据长度: {len(data)} 样本")
    
    # 生成C/C++头文件
    os.makedirs(os.path.dirname(output_header), exist_ok=True)
    
    # 生成头文件名（不含路径）
    header_basename = os.path.basename(output_header)
    header_guard = header_basename.upper().replace('.', '_')
    
    with open(output_header, 'w') as f:
        # 写入头文件保护宏
        f.write(f"#ifndef {header_guard}\n")
        f.write(f"#define {header_guard}\n\n")
        f.write("#include <stdint.h>\n\n")
        
        # 写入音频参数宏
        f.write(f"#define AUDIO_SAMPLE_RATE {target_sample_rate}\n")
        f.write(f"#define AUDIO_BIT_DEPTH 16\n")
        f.write(f"#define AUDIO_LENGTH {len(data)}\n\n")
        
        # 生成音频数组名（基于文件名）
        array_name = os.path.splitext(header_basename)[0].replace('-', '_')
        f.write(f"const uint16_t {array_name}_data[] = {{\n")

        # 输出数据，每行8个
        for i, sample in enumerate(data):
            # 转换为无符号16位（0-65535）用于存储
            unsigned_sample = sample + 32768
            f.write(f"0x{unsigned_sample:04X}")
            if i < len(data) - 1:
                f.write(", ")
            if (i + 1) % 8 == 0:
                f.write("\n")
        
        f.write("\n};\n\n")
        
        # 添加便捷访问宏
        f.write(f"#define AUDIO_DATA {array_name}_data\n")
        f.write(f"#define AUDIO_DATA_LEN AUDIO_LENGTH\n\n")
        
        # 添加12位有效数据提取宏（如果需要）
        f.write(f"// 从16位数据中提取12位有效值 (高12位)\n")
        f.write(f"#define EXTRACT_12BIT(x) (((x) >> 4) & 0x0FFF)\n\n")
        
        f.write(f"#endif // {header_guard}\n")
    
    return True


def batch_generate_headers():
    """批量生成C头文件（16kHz采样率）"""
    os.makedirs(HEADER_DIR, exist_ok=True)
    
    # 从最终12位WAV目录读取
    wav_files = [f for f in os.listdir(FINAL_DIR) if f.endswith(".wav")]
    
    if not wav_files:
        print("警告：最终WAV目录中没有找到文件")
        return False
    
    print("\n开始生成C头文件 (采样率: {}Hz)...".format(TARGET_SAMPLE_RATE))
    print("=" * 60)
    
    success_count = 0
    for filename in wav_files:
        input_path = os.path.join(FINAL_DIR, filename)
        base_name = os.path.splitext(filename)[0]
        output_header = os.path.join(HEADER_DIR, base_name + ".h")
        
        print(f"\n处理: {filename}")
        if generate_c_header(input_path, output_header, TARGET_SAMPLE_RATE):
            success_count += 1
            print(f"  ✓ 头文件已生成: {output_header}")
    
    print("\n" + "=" * 60)
    print(f"✓ 头文件生成完成！成功: {success_count}/{len(wav_files)}，保存于：{HEADER_DIR}")
    return success_count > 0


# ==================== 第五步：可选 - 直接从原始文件生成头文件（16kHz） ====================
def generate_header_from_original():
    """直接从原始WAV文件生成C头文件（16kHz采样率）"""
    os.makedirs(HEADER_DIR, exist_ok=True)
    
    wav_files = [f for f in os.listdir(INPUT_DIR) 
                 if f.lower().endswith(".wav")]
    
    if not wav_files:
        print("警告：原始目录中没有WAV文件")
        return False
    
    print("\n直接从原始文件生成C头文件 (采样率: {}Hz)...".format(TARGET_SAMPLE_RATE))
    print("=" * 60)
    
    success_count = 0
    for filename in wav_files:
        input_path = os.path.join(INPUT_DIR, filename)
        base_name = os.path.splitext(filename)[0]
        output_header = os.path.join(HEADER_DIR, base_name + "_direct.h")
        
        print(f"\n处理: {filename}")
        if generate_c_header(input_path, output_header, TARGET_SAMPLE_RATE):
            success_count += 1
            print(f"  ✓ 头文件已生成: {output_header}")
    
    print("\n" + "=" * 60)
    print(f"✓ 直接生成完成！成功: {success_count}/{len(wav_files)}")
    return success_count > 0


# ==================== 主函数 ====================
def main():
    """主控制流程"""
    print("音频处理工具 v2.0 - 完整版 (16kHz采样率)")
    print("=" * 60)
    print(f"功能：")
    print(f"  1. 转换采样率 ({TARGET_SAMPLE_RATE}Hz) 和音量")
    print(f"  2. 转换为12位深度WAV")
    print(f"  3. 生成C头文件 ({TARGET_SAMPLE_RATE}Hz, 16位存储)\n")
    print("=" * 60)
    
    original_dir = os.getcwd()
    
    try:
        # 第一步：转换采样率和音量
        if not convert_sample_rate_and_volume():
            print("❌ 采样率转换失败")
            return
        
        # 第二步：分析转换后的文件
        analyze_wav_files()
        
        # 第三步：转换为12位深度WAV
        convert_to_12bit_wav()
        
        # 第四步：批量生成C头文件（16kHz）
        batch_generate_headers()
        
        # 可选：直接从原始文件生成头文件
        # generate_header_from_original()
        
        # 返回原始目录
        os.chdir(original_dir)
        
        print("\n" + "=" * 60)
        print("✅ 所有处理步骤完成！")
        print(f"\n输出文件位置：")
        print(f"  - {TARGET_SAMPLE_RATE}Hz WAV: {TEMP_DIR}/")
        print(f"  - 12位 WAV: {FINAL_DIR}/")
        print(f"  - C头文件: {HEADER_DIR}/")
        
    except Exception as e:
        print(f"\n❌ 处理过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        os.chdir(original_dir)  # 确保返回原始目录


# ==================== 单独使用头文件生成功能 ====================
def standalone_header_generation():
    """单独使用头文件生成功能（不经过前面的转换步骤）"""
    print("单独生成C头文件模式 (16kHz采样率)")
    print("=" * 60)
    
    # 可以选择从哪个目录读取WAV文件
    source_dir = input("请输入WAV文件目录 (直接回车使用当前目录): ").strip()
    if not source_dir:
        source_dir = INPUT_DIR
    
    os.chdir(source_dir)
    wav_files = [f for f in os.listdir() if f.endswith(".wav")]
    
    if not wav_files:
        print("未找到WAV文件")
        return
    
    header_dir = os.path.join(source_dir, "headers")
    os.makedirs(header_dir, exist_ok=True)
    
    for filename in wav_files:
        base_name = os.path.splitext(filename)[0]
        output_header = os.path.join(header_dir, base_name + ".h")
        print(f"\n处理: {filename}")
        generate_c_header(filename, output_header, TARGET_SAMPLE_RATE)
        print(f"  ✓ 头文件已生成: {output_header}")
    
    print(f"\n✅ 头文件保存于：{header_dir}")


# ==================== 入口 ====================
if __name__ == "__main__":
    # 运行完整流程
    main()
    
    # 如果只需要生成头文件，取消下面的注释
    # standalone_header_generation()
