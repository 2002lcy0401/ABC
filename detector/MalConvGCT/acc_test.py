from MalConvGCT_nocat import MalConvGCT
import torch
import numpy as np
import torch.nn.functional as F
import os

# 初始化模型并加载权重
mlgct = MalConvGCT(channels=256, window_size=256, stride=64)
checkpoint = torch.load("malconvGCT_nocat.checkpoint", map_location='cpu')
mlgct.load_state_dict(checkpoint['model_state_dict'], strict=False)

def predict(file_path):
    """对单个文件进行预测"""
    with open(file_path, 'rb') as infile:
        bytez = infile.read()
    _inp = torch.from_numpy(np.frombuffer(bytez, dtype=np.uint8)[np.newaxis, :])
    with torch.no_grad():
        outputs = F.softmax(mlgct(_inp), dim=-1)
    return outputs.detach().numpy()[0]

def evaluate_dataset(dataset_path, label):
    """评估数据集并计算准确率"""
    correct_predictions = 0
    total_files = 0
    for file_name in os.listdir(dataset_path):
        file_path = os.path.join(dataset_path, file_name)
        if os.path.isfile(file_path):
            prediction = predict(file_path)
            predicted_label = np.argmax(prediction)
            if predicted_label == label:
                correct_predictions += 1
            total_files += 1
    accuracy = correct_predictions / total_files if total_files > 0 else 0
    return accuracy, total_files

if __name__ == '__main__':
    import sys
    benign_dataset_path = sys.argv[1]
    malware_dataset_path = sys.argv[2]

    # 评估良性软件数据集
    benign_accuracy, benign_total = evaluate_dataset(benign_dataset_path, label=1)
    print(f"Benign dataset accuracy: {benign_accuracy:.2f} ({benign_total} samples)")

    # 评估恶意软件数据集
    malware_accuracy, malware_total = evaluate_dataset(malware_dataset_path, label=0)
    print(f"Malware dataset accuracy: {malware_accuracy:.2f} ({malware_total} samples)")
