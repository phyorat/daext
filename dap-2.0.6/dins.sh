#!/bin/bash

#rm -R /usr/local/include
#rm -R /usr/local/lib
mv /usr/local/include /usr/local/include_rt
mv /usr/local/lib /usr/local/lib_rt

ln -s /usr/local/lib_daq_206 /usr/local/lib
#ln -s /usr/local/include_daq_206 /usr/local/include
ln -s /usr/local/include_daq_fake /usr/local/include

make install

rm /usr/local/include
rm /usr/local/lib

mv /usr/local/include_rt /usr/local/include
mv /usr/local/lib_rt /usr/local/lib

