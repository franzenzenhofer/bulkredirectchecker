from setuptools import setup, find_packages

setup(
    name='bulkredirectchecker',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'requests',
        'tqdm',
        # add other dependencies here
    ],
    entry_points={
        'console_scripts': [
            'bulkredirectchecker = bulkredirectchecker:main',
        ],
    },
)