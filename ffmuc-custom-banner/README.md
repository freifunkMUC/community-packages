# ffmuc-custom banner

This package modifies the /etc/banner that is shown during SSH login.

⚠️ This package will consume an additional 2x the banner size, one for the template and one for the final banner. Make sure to have enough flash size available.


### Configuration

You should use something like the following in the site.conf:

```lua
custom_banner = {
    enabled = true,
    map_url = 'https://map.ffmuc.net/#!/',
    },
```
