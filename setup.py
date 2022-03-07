from setuptools import setup

__version__ = '1.0.0'

setup(
    name='pyialarmxr',
    py_modules=["pyialarmxr"],
    version=__version__,
    description='A simple library to interface with iAlarmXR systems, built for use with Home Assistant',
    author='Fabio Mauro, Ludovico de Nittis',
    author_email='bigmoby.pyialarmxr@gmail.com',
    url='https://github.com/bigmoby/pyialarmxr',
    download_url='https://github.com/bigmoby/pyialarmxr',
    license='MIT License',
    classifiers=[
      'Development Status :: 4 - Beta',
      'Intended Audience :: Developers',
      'Programming Language :: Python :: 3',
    ],
    keywords=['ialarmXR', 'antifurtocasa365', 'alarm'],
    packages=['pyialarmxr'],
    include_package_data=True,
    install_requires=['lxml', 'xmltodict'],
)
