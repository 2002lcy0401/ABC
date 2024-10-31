import torch
import torch.nn.functional as F
from detector.malware_evasion_competition.MalConv import MalConv
from ember import predict_sample
from detector.MalConvGCT.MalConvGCT_nocat import MalConvGCT
import lightgbm as lgb
import numpy as np
import os
import clamav
import avast

MALCONV_MODEL_PATH = 'detector/malware_evasion_competition/models/malconv/malconv.checkpoint'
NONNEG_MODEL_PATH = 'detector/malware_evasion_competition/models/nonneg/nonneg.checkpoint'
EMBER_MODEL_PATH = 'detector/malware_evasion_competition/models/ember/ember_model.txt'
MalConvGCT_MODEL_PATH = 'detector/MalConvGCT/malconvGCT_nocat.checkpoint'

class MalConvModel(object):
    def __init__(self, model_path, thresh=0.5, name='malconv'): 
        self.model = MalConv(channels=256, window_size=512, embd_size=8).train()
        weights = torch.load(model_path,map_location='cpu')
        self.model.load_state_dict( weights['model_state_dict'])
        self.thresh = thresh
        self.__name__ = name

    def predict(self, bytez):
        _inp = torch.from_numpy( np.frombuffer(bytez,dtype=np.uint8)[np.newaxis,:] )
        with torch.no_grad():
            outputs = F.softmax( self.model(_inp), dim=-1)

        return outputs.detach().numpy()[0,1],outputs.detach().numpy()[0,1]> self.thresh
        return outputs.detach().numpy()[0,1]> self.thresh

class EmberModel(object):
    # ember_threshold = 0.8336 # resulting in 1% FPR
    def __init__(self, model_path=EMBER_MODEL_PATH, thresh=0.8336, name='ember'):
        # load lightgbm model
        self.model = lgb.Booster(model_file=model_path)
        self.thresh = thresh
        self.__name__ = 'ember'

    def predict(self,bytez):
        return predict_sample(self.model, bytez),predict_sample(self.model, bytez) > self.thresh
        return predict_sample(self.model, bytez) > self.thresh
        # return predict_sample(self.model, bytez)
    

class MalConvGCTModel(object):
    def __init__(self, model_path, thresh=0.5, name='malconvGCT'): 
        self.model = MalConvGCT(channels=256, window_size=256, stride=64)
        weights = torch.load(model_path,map_location='cpu')
        self.model.load_state_dict(weights['model_state_dict'], strict=False)
        self.thresh = thresh
        self.__name__ = name

    def predict(self, bytez):
        _inp = torch.from_numpy( np.frombuffer(bytez,dtype=np.uint8)[np.newaxis,:] )
        with torch.no_grad():
            outputs = F.softmax(self.model(_inp), dim=-1)
        return outputs.detach().numpy()[0,1],outputs.detach().numpy()[0,1]> self.thresh 
        return outputs.detach().numpy()[0,1]> self.thresh  ##1代表是恶意的

class ClamavModel(object):
    def __init__(self,name='clamav'): 
        self.__name__ = name

    def predict(self,mal_path):
        result = clamav.scan_with_pyclamd(mal_path)
        if result == 1:
            return 1
            # print("The file is malicious.")
        else:
            return 0

class AvastModel(object):
    def __init__(self,name='avast'): 
        self.__name__ = name

    def predict(self,mal_path):
        result = avast.scan_with_avast(mal_path)
        if result == 1:
            return 1
            # print("The file is malicious.")
        else:
            return 0



def predit_label(model,file_path):
    if model.__name__ == 'malconv' or model.__name__ == 'malconvGCT' or model.__name__ == 'ember' : 
       
        """对单个文件进行预测"""
        with open(file_path,'rb') as infile:
            bytez = infile.read()
        score,hard_label = model.predict(bytez)
        return score,hard_label
    else:
        hard_label = model.predict(file_path)
        score = hard_label
        return score,hard_label




if __name__ == '__main__':
    malware_dir = 'dataset/malware'
    malconv = MalConvModel( MALCONV_MODEL_PATH, thresh=0.5 )
    ember = EmberModel(EMBER_MODEL_PATH, thresh=0.8336 )
    malconvGCT = MalConvGCTModel(MalConvGCT_MODEL_PATH, thresh=0.5)
    models = [malconv,ember,malconvGCT]
    malware_list = os.listdir(malware_dir)
    i=1
    for malware in malware_list:
        print(f'processing {i}/{len(malware_list)}')
        malware_path = os.path.join(malware_dir,malware)
        malware_path = os.path.normpath(malware_path)
        with open(malware_path,'rb') as infile:
            bytez = infile.read()
        for m in models:
            if m.predict(bytez)[1]:
                continue
            else:
                print(f'{malware} is detected as benign, remove it')
                os.remove(malware_path)
                break
        i+=1


  