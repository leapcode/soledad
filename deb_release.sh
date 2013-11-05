#!/bin/zsh

cd common
echo `pwd`
rm src/leap/soledad/common/_version.py
python setup.py freeze_debianver
sed -i 's/-dirty//g' src/leap/soledad/common/_version.py 
cd ..

cd client
rm src/leap/soledad/client/_version.py
python setup.py freeze_debianver
sed -i 's/-dirty//g' src/leap/soledad/client/_version.py 
cd ..

cd server
rm src/leap/soledad/server/_version.py
python setup.py freeze_debianver
sed -i 's/-dirty//g' src/leap/soledad/server/_version.py 
cd ..

git add common/src/leap/soledad/common/_version.py
git add client/src/leap/soledad/client/_version.py
git add server/src/leap/soledad/server/_version.py
git ci -m "freeze debian version"	
