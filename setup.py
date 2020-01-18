import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='trustyroles',
    version='1.1.8',
    description='AWS roles toolkit',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    url='https://github.com/hmcguire1/trustyroles',
    author_email='hmcguire.dev@gmail.com',
    author='hmcguire1',
    install_requires=[
        'boto3'
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points = {
        'console_scripts': ['arpd_update=trustyroles.arpd_update.arpd_update:_main'],
    },
    python_requires='>=3.6'
)
