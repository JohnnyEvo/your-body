let mix = require('laravel-mix');

require('dotenv/config');
require('laravel-mix-tailwind');
require('laravel-mix-svelte');

mix.js('resources/js/main.js', 'dist').
    sass('resources/css/tailwind.scss', 'dist').
    setPublicPath('public').
    tailwind().
    svelte();
