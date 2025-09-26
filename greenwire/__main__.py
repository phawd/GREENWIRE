import runpy
import os


def main():
    """Execute the top-level GREENWIRE CLI script in-place.

    This helper allows packaging to expose a console script that runs
    the existing top-level `greenwire.py` script without renaming the
    file. Using `python -m greenwire` will also execute this main.
    """
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'greenwire.py'))
    if os.path.exists(script_path):
        runpy.run_path(script_path, run_name='__main__')
    else:
        print('ERROR: top-level greenwire.py script not found.')


if __name__ == '__main__':
    main()
