---
description: Easy 🔮 Web
cover: https://i.pinimg.com/564x/65/e2/0a/65e20aeab7d1b5e314d218a828c3b022.jpg
coverY: 0
layout:
  cover:
    visible: true
    size: hero
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# JsCalc

## Source code

<figure><img src="../../../../.gitbook/assets/image (120).png" alt=""><figcaption></figcaption></figure>

* **Module Export:**
  * <mark style="color:red;">**`module.exports`**</mark> is a special object in Node.js that allows you to export functions, objects, or primitives from a given file so that they can be used in other files via <mark style="color:red;">**`require`**</mark>.
* **`calculate` Function:**
  * This function takes a single argument <mark style="color:red;">**`formula`**</mark>, which is expected to be a string containing a mathematical expression.
* **`try-catch` Block:**
  * The code within the <mark style="color:red;">**`try`**</mark> block attempts to evaluate the formula using the <mark style="color:red;">**`eval`**</mark> function.
  * If an error occurs during the evaluation, the <mark style="color:red;">**`catch`**</mark> block checks if the error is a <mark style="color:red;">**`SyntaxError`**</mark>. If it is, the function returns the string <mark style="color:red;">**`'Something went wrong!'`**</mark>.
*   **`eval` Function:**

    * The core operation is performed by <mark style="color:red;">**`eval`**</mark>, which is a built-in JavaScript function that executes a string of code.
    * In this case, the <mark style="color:red;">**`eval`**</mark> function is wrapped inside an immediately invoked function expression (IIFE) to ensure that the evaluated formula is executed in its local scope.

    ```javascript
    eval(`(function() { return ${ formula } ;}())`);
    ```

    * The string passed to `eval` creates a function, immediately executes it, and returns the result.
    * For example, if **`formula`** is <mark style="color:red;">**`'2 + 2'`**</mark>, the <mark style="color:red;">**`eval`**</mark> function effectively evaluates the expression <mark style="color:red;">**`2 + 2`**</mark> and returns <mark style="color:red;">**`4`**</mark>.
* **Error Handling:**
  * If the <mark style="color:red;">**`eval`**</mark> call results in a <mark style="color:red;">**`SyntaxError`**</mark>, the catch block returns <mark style="color:red;">**`'Something went wrong!'`**</mark> to indicate that the input formula was not valid.
  * This error handling only covers syntax errors, so other types of errors (e.g., <mark style="color:red;">**`ReferenceError`**</mark>) would not be caught and could potentially cause the function to fail without returning any indication of what went wrong.

The <mark style="color:red;">**`eval()`**</mark> function in JavaScript is a global function that evaluates a string as an expression and returns the results. This function can execute both expressions and statements contained within the string.

The use of <mark style="color:orange;">**`eval`**</mark> is inherently risky, especially when processing user input because it can execute any JavaScript code, not just mathematical expressions. This introduces a significant security vulnerability called **code injection**

## Exploit (The danger of eval function)

<figure><img src="../../../../.gitbook/assets/image (121).png" alt=""><figcaption></figcaption></figure>

Now, considering this code, when you pass the following input as the <mark style="color:red;">**`formula`**</mark>:

```javascript
"require('fs').readFileSync('/flag.txt').toString();"
```

#### How It Works:

1. <mark style="color:red;">**`formula`**</mark>**&#x20;String in&#x20;**<mark style="color:red;">**`calculate`**</mark>**:**
   * The <mark style="color:red;">**`formula`**</mark> you provided is <mark style="color:red;">**`"require('fs').readFileSync('/flag.txt').toString();"`**</mark>.
2.  **`eval` Execution:**

    * The <mark style="color:red;">**`eval`**</mark> function is used to evaluate the <mark style="color:red;">**`formula`**</mark>. Inside the <mark style="color:red;">**`eval`**</mark>, the string you passed is inserted into a dynamically created function:

    ```javascript
    eval(`(function() { return require('fs').readFileSync('/flag.txt').toString(); }())`);
    ```

    * This string gets executed as JavaScript code.
3. **What Happens During Execution:**
   * <mark style="color:red;">**`require('fs')`**</mark>: The <mark style="color:red;">**`fs`**</mark> (File System) module is required to access the file system.
   * <mark style="color:red;">**`readFileSync('/flag.txt')`**</mark>: This function reads the contents of the file <mark style="color:red;">**`flag.txt`**</mark> synchronously. The content is returned as a <mark style="color:red;">**`Buffer`**</mark> object, which is a raw representation of the file's binary data.
   * <mark style="color:red;">**`.toString()`**</mark>: Since **`readFileSync`** returns a <mark style="color:red;">**`Buffer`**</mark>, calling <mark style="color:red;">**`.toString()`**</mark> on this <mark style="color:red;">**`Buffer`**</mark> converts it from binary data into a human-readable string format. Without calling <mark style="color:red;">**`.toString()`**</mark>, the returned value would be a <mark style="color:red;">**`Buffer`**</mark> object, not a string.
4. **Return Value:**
   * The function will then return the content of the <mark style="color:red;">**`flag.txt`**</mark> file as a string because the **`toString()`** method converts the binary **`Buffer`** data into a string. This string is then returned by the **`calculate`** function.

#### Why <mark style="color:red;">`.toString()`</mark> is Important here:

* The <mark style="color:red;">**`.toString()`**</mark> method is used here to convert the binary <mark style="color:red;">**`Buffer`**</mark> returned by <mark style="color:red;">**`readFileSync`**</mark> into a readable string. This is necessary to work with the file's content as text, making it suitable for output or further processing. However, using <mark style="color:red;">**`eval`**</mark> with untrusted input, as in this code, is highly dangerous and can lead to severe security vulnerabilities.
* **Raw Buffer vs. Readable String:**
  * The <mark style="color:red;">**`readFileSync`**</mark> function returns the file contents as a <mark style="color:red;">**`Buffer`**</mark> because it doesn’t assume the data is text. A <mark style="color:red;">**`Buffer`**</mark> is a representation of binary data. If you want to work with this data as text (e.g., to display it, concatenate it, or process it as a string), you need to convert it to a string.
  * By using <mark style="color:red;">**`.toString()`**</mark>, the binary content of the file (which might be stored in **UTF-8** encoding, for example) is decoded into a readable string.

