from setuptools import setup

setup(
    name='open_flask_auth',
    version='1.0.0',
    packages=['open_flask_auth'],
    # package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'Flask==2.0.1',
        'pyjwt'
    ],
)
