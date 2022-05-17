module.exports = {
  content: [
      './resources/views/**/*.{twig,html}',
      './resources/js/**/*.{js,svelte}',
  ],
  theme: {
    extend: {
      colors: {
        primary: '#0F493F',
        secondary: '#FACDCA',
        accent: '#000000',
      },
    },
  },
  plugins: [],
};
