from setuptools import setup

__version__ = '1.0.0'

setup(
    name='pymeianlike',
    py_modules=["pymeianlike"],
    version=__version__,
    description='A simple library to interface with a Meianlike systems.',
    author='Fabio Mauro, Ludovico de Nittis',
    author_email='bigmoby.pymeianlike@gmail.com',
    url='https://github.com/bigmoby/pymeianlike',
    download_url='https://github.com/bigmoby/pymeianlike',
    license='MIT License',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
    ],
    keywords=['meianlike', 'alarm'],
    packages=['pymeianlike'],
    include_package_data=True,
    install_requires=['lxml'],
)
