# Dependencies

# phoenixAES: a tool to perform differential fault analysis attacks (DFA) against AES
# r2pipe permits interacting with r2 instances
# git clone https://github.com/SideChannelMarvels/Stark 

python3 -m pip install phoenixAES
python3 -m pip install r2pipe
git clone https://github.com/SideChannelMarvels/Stark 
cd Stark
make
cd ..
python3 ./solve.py


