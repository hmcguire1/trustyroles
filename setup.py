import setuptools

setuptools.setup(
    name='trustyroles',
    version='0.0.2',
    description='AWS roles toolkit',
    packages=setuptools.find_packages(),
    url='https://github.com/hmcguire1/trustyroles',
    author_email='hmcguire8621@gmail.com',
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
        'console_scripts': ['arpd_update=trustyroles.arpd_update:_main'],
    },
    python_requires='>=3.6'
)
