"""Enable ``python -m sentryai`` entry point.

Delegates entirely to the CLI module's ``main()`` function.
"""

from sentryai.cli import main

if __name__ == "__main__":
    main()
