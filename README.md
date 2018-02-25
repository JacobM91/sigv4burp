# sigv4burp
This extention will re-sign new requests with sigv4 through burp suite.

# How to get your tokens for URL way?
 1. Open Chrome browser.
 2. Right click on any place and then inspect.
 3. Click on Network tab.
 4. Navigate to identity.magicleap.io
 5. You'll see request to https://auth.magicleap.io/signin?client_id=com.magicleap.web.identity&redirect_uri=https%3A%2F%2Fidentity.magicleap.io%2Fauth&continue_to=%2F
 6. Copy the Location value to Sigv4 tab.
 Which looks like, https://identity.magicleap.io/auth#access_token=........

# How to install
 1. git clone git@github.com:slevi2103/sigv4burp.git
 2. Open Burp Suite.
 4. Navigate to Extender tab.
 5. Click on Extensions tab.
 6. Click Add button.
 7. Under Extension Details click on Python as your Extension type.
 8. Click on Select file .. and select sigv4.py from git directory.
 9. Click Next and then Close. (Check that no errors raised during the upload).
 10.a Sigv4 tab will be added to burp suite.

Now, each time you'll do repeater/proxy request the extender will re-sign your request.
