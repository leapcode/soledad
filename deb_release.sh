#!/bin/zsh

for pkg in common client server; do
  cd ${pkg}
  echo `pwd`
  rm src/leap/soledad/${pkg}/_version.py
  python setup.py freeze_debianver
  sed -i 's/-dirty//g' src/leap/soledad/${pkg}/_version.py 
  git add src/leap/soledad/${pkg}/_version.py
  cd ..
done

git commit -m "freeze debian version"
