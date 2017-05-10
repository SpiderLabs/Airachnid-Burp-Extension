# Airachnid Burp Extension
A Burp extension to test applications for vulnerability to the Web Cache Deception attack.

Once the extension has been loaded, it can be accessed in the Target - Sitemap tab and right click on the resource that should be tested. A context sensitive menu item called "Airachnid Web Cache Test" will be shown and can be used to conduct testing. If the resource is vulnerable, an Issue is created detailing the vulnerability.

The context sensitive menu item is also available for requests in the Proxy - Http History tab.

## Installation
* Download the Airachnid.jar file.
* In Burp Suite open Extender tab. In Extensions tab, click Add button.
* Choose downloaded jar file -> Next.
* Check installation for no error messages.

## Vulnerability
In February 2017, security researcher Omer Gil unveiled a new attack vector dubbed “Web Cache Deception” (https://omergil.blogspot.co.il/2017/02/web-cache-deception-attack.html).

The Web Cache Deception attack could be devastating in consequences, but is very simple to execute:
1. Attacker coerces victim to open a link on the valid application server containing the payload.
2. Attacker opens newly cached page on the server using the same link, to see the exact same page as the victim.

** *Of course, this attack only makes sense when the vulnerable resource available to the attacker returns sensitive data.*

The attack depends on a very specific set of circumstances to make the application vulnerable:
**1. The application only reads the first part of the URL to determine the resource to return.**   
If the victim requests:  
```
https://www.example.com/my_profile
```
The application returns the victim profile page. The application uses only the first part of the URL to determine that the profile page should be returned. If the application receives a request for
```
https://www.example.com/my_profile_test
```
It would still return the profile page of the victim, disregarding the added text. The same applies for other URL like
```
https://www.example.com/my_profile/test
```
**2. The application stack caches resources according to their file extensions, rather than by cache header values.**
If the application stack has been configured to cache image files. It will cache all resources with `.jpg` `.png` or `.gif` extensions. That means that e.g. the image at  

```
https://www.example.com/images/dog.jpg
```

Would be retrieved from the application server the first time the image is requested. All subsequent requests for the image are retrieved from cache, responding with the same resource that was initially cached (for as long as the cache timeout is set).

## Attack
These preconditions can be exploited for the Web Cache Deception attack in the following manner:
 
### Step 1: An attacker entices the victim to open a maliciously crafted link:
  https://www.example.com/my_profile/test.jpg
 
* The application ignores the 'test.jpg' part of the URL, the victim profile page is loaded.
* The caching mechanism identifies the resource as an image, caching it.
 
### Step 2: The attacker sends a GET request for the cached page:
  https://www.example.com/my_profile/test.jpg
 
* The cached resource, which is in fact the victim profile page is returned to the attacker (and to anyone else requesting it).

*MIND BLOWN* How easy is that?
