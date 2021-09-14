help:
	@sed -n 's/\(^[-a-zA-Z_]\+\):.*/make \1/p' Makefile

sdist: checkdocs
	python3 setup.py sdist

dist: sdist

venv:
	python3 -m venv venv

upload: dist
	twine upload dist/*.tar.gz

upload-test: dist
	twine upload --repository testpypi dist/*.tar.gz

clean: clean-dist clean-build clean-egg

clean-all: clean clean-venv

clean-dist:
	rm -rfv dist

clean-build:
	rm -rfv build

clean-egg:
	rm -rfv aws_test_*.egg-info

clean-venv:
	rm -rfv venv

local:
	pip install .

checkdocs:
	python setup.py checkdocs

.PHONY: help clean clean-all clean-dist clean-build clean-egg clean-venv checkdocs
