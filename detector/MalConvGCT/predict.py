from MalConvGCT_nocat import MalConvGCT
import torch
import numpy as np
import torch.nn.functional as F

mlgct = MalConvGCT(channels=256, window_size=256, stride=64)
x = torch.load("malconvGCT_nocat.checkpoint",map_location='cpu')
mlgct.load_state_dict(x['model_state_dict'], strict=False)


if __name__ == '__main__':
    import sys
    with open(sys.argv[1],'rb') as infile:
        bytez = infile.read()
    _inp = torch.from_numpy( np.frombuffer(bytez,dtype=np.uint8)[np.newaxis,:] )
    with torch.no_grad():
        outputs = F.softmax(mlgct(_inp), dim=-1)
    print(outputs.detach().numpy()[0,1]) 