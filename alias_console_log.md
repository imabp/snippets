Want to have a console.log alias we can use this code.


```js
cl = function() { return console.log.apply(console, arguments); };


```

Usage

```js
cl(value);
```
