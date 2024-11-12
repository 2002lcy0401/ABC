# MiniMal: Hard-Label Adversarial Attack Against Static Malware Detection With Minimal Perturbation



## 1. Download dataset

Our data comes from two sources:

- https://doi.org/10.6084/m9.figshare.6635642.v1
- [MalwareBazaar | Malware sample exchange](https://bazaar.abuse.ch/)

The malware hash names we use are stored in **malware_dataset-name.txt**, and you can directly find them in the sources of the two datasets above.

The benign dataset comes from https://doi.org/10.6084/m9.figshare.6635642.v1 

## 2. Target Detector

**For three ML detector：MalConv、Ember and MalGCG**

MalConv and Ember：[endgameinc/malware_evasion_competition](https://github.com/endgameinc/malware_evasion_competition)

MalGCG：[FutureComputing4AI/MalConv2: Classifying Sequences of Extreme Length with Constant Memory Applied to Malware Detection](https://github.com/FutureComputing4AI/MalConv2)

**For two commercial anti virus products：ClamAV and Avast**

ClamAV：[ClamAVNet](https://www.clamav.net/)

Avast：https://www.avast.com/

## 3. Run MiniMal

**Channel.py**

- Change your malware path to "mal_dir"
- Change your benign software path to "ben_dir"
- Change your target detector path to "attack_model"

Then you can run it just by **"python channel.py"**

And if you want to check PE file functionality，you need to download IDA pro ,and place the **"cfg.py"** to the IDA pro dir path (see the **"get_cfg.py"**)