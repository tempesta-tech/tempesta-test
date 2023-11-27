# tempesta-tech.com test

1. cd into `tempesta-tech.com` repository.
2. switch to `mb-83-docker` branch.
3. make a symbolic link to `docker_compose` directory.
4. run `test_tempesta_tech` test.

```
ls
tempesta-tech.com   tempesta-test

cd tempesta-tech.com
git checkout mb-83-docker
git pull
ln -s $PWD ../tempesta-test/docker_compose/tempesta-tech.com
cd ..

cd tempesta-test
./run_tests.py t_sites.test_tempesta_tech
```
