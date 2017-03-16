from setuptools import setup
'''sudo python setup.py install'''

setup(
    name="scurl",
    version='0.1',
    py_modules=['main'],
    entry_points='''
        [console_scripts]
        scurl=scurl:main
    '''
)
