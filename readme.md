# Aiwos Two-Factor

Customized forked plugin for Portal2. Original plugin: https://github.com/WordPress/two-factor

## Usage

See the [readme.txt](readme.txt) for installation and usage instructions.

## Development

To use the provided development environment, you'll first need to install and launch Docker. Once it's running, the next steps are:

    $ git clone https://github.com/wordpress/two-factor.git
    $ cd two-factor
    $ npm install
    $ npm run build
    $ npm run env start

See `package.json` for other available scripts you might want to use during development, like linting and testing.

## Testing

1. Run `npm test` or `npm run test:watch`.

To generate a code coverage report, be sure to start the testing environment with coverage support enabled:
    npm run env start -- --xdebug=coverage

To view the code coverage report, you can open a web browser, go to `File > Open file...`, and then select `{path to two-factor}/tests/logs/html/index.html`.
