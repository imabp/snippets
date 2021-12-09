I was going through the problem of setting up custom fonts in a NextJS - Tailwind Setup 
Something that helped me to solve this is here:

Got to  global styles file, and import the font file.

```css
@tailwind base;
@tailwind components;

@font-face {
  font-family: 'Roboto';
  src: local('Roboto'), url(./fonts/Roboto-Regular.ttf) format('ttf');
}

@tailwind utilities;
```

Setup the tailwind config with extended fontFamily.
This makes sure, that tailwind wont mess up default with custom fonts.

```js
module.exports = {
  theme: {
    extend: {
      fontFamily: {
        'sans': ['Roboto', 'Helvetica', 'Arial', 'sans-serif']
      }
    },
  },
  variants: {},
  plugins: []
}
```
