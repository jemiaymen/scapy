#%%
from api import *

#%%

iface = 'wlp0s20f3'
send(iface=iface,msg='Hello word',show_pkt=True , dst='127.0.0.1')
#%%
pkt = get_pkt()


print('\n')
print('----------- encapsulate pkt ------------')
print('\n')


pkt2 = encapsulate(pkt,iface=iface,dst='127.0.0.1')
# %%
