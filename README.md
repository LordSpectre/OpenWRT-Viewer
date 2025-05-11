OpenWrt Firewall Viewer

Overview:
Coming from applications like pfSense or OPNSense, the only thing I've missed since migrating to OpenWRT is a clear view of the Firewall rules. LuCI displays all rules on a single page, and honestly, it's quite confusing, especially if you need to see at a glance which rule might be blocking your connection at that moment (without having to enable logs).

This small graphical interface lists all the zones configured on your OpenWRT and divides the firewall rules (including Port Forwarding) into different tabs. It also allows you to enable/disable rules with a click. I haven't added other modifications to the rules, as LuCI already does that very well. The GUI is simple, nothing fancy, but you can easily customize it by changing the CSS part.

NOTE: In my environment, I have an Ubuntu VM where I run everything. Obviously, you can use any web server you want. Below are the step-by-step instructions to install everything on Ubuntu.

Requirements:

- An Ubuntu server (LTS version recommended, e.g., 22.04 or 24.04).
- Root or sudo access to the Ubuntu server.
- An OpenWrt router accessible on the network from the Ubuntu server, with SSH enabled.
- Credentials (root user and password) to access the OpenWrt router via SSH.
*IMPORTANT*: The /etc/config/firewall file on OpenWrt must have explicit section names (e.g., config rule 'MyRules') for the rule enable/disable feature (UCI Commands) to function optimally.

Step 1: Ubuntu Server Preparation

Update the system:
apt update
apt upgrade -y

Install Apache (Web Server):
apt install -y apache2

Enable Apache to start on boot:
systemctl enable apache2
systemctl start apache2

Install PHP and necessary extensions: We will use PHP 8.3 (common on Ubuntu 24.04, adjust the version if necessary for other Ubuntu releases). phpseclib (used by the project) is compatible.
apt install -y php8.3 libapache2-mod-php8.3 php8.3-cli php8.3-common php8.3-mbstring php8.3-xml php8.3-curl unzip

Enable the PHP module for Apache:
a2enmod php8.3

Install Composer (Dependency Manager for PHP):

cd ~
curl -sS https://getcomposer.org/installer -o composer-setup.php
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
rm composer-setup.php

Step 2: Get the Application Code
Clone or Download the Project. Let's assume you clone it into /var/www/html/.

If you don't use git, download the source files (make sure they contain index.php, favicon.ico, .htaccess, and the composer.json file) and upload them to /var/www/html/
Ensure you have a composer.json file in your project root with at least this content (for phpseclib):

{
    "require": {
        "phpseclib/phpseclib": "~3.0"
    }
}

Install PHP Dependencies: Navigate to the project directory and let Composer install phpseclib:

cd /var/www/html/
composer install --no-dev --optimize-autoloader

This will create the vendor/ directory with the necessary libraries. (If you already have the vendor/ directory in your repository and don't want to use composer, you can skip this step, but using composer is recommended).

Step 3: index.php Application Configuration

Modify Credentials: Open the index.php file (located at /var/www/html/index.php) with a text editor:
nano /var/w ww/html/index.php

Find and modify the following lines with YOUR OpenWrt router details:

At the beginning of the file, for AJAX handling:

$ajax_router_ip = '192.168.1.1'; // Your OpenWrt router IP
$ajax_username = 'root';         // SSH user for OpenWrt
$ajax_password = '[root_password]';  // SSH password for OpenWrt
Further down, for the initial page load:

$router_ip = '192.168.1.1'; // Your OpenWrt router IP
$username = 'root';        // SSH user for OpenWrt
$password = '[root_password]'; // SSH password for OpenWrt
*SECURITY WARNING*: Storing passwords in plain text in the code is not ideal for security. For personal use on a trusted network, it might be acceptable, but for wider deployments, consider alternatives like SSH key authentication.

Step 6: Ubuntu Server Firewall (if active)
If ufw (Uncomplicated Firewall) is active on your Ubuntu server, allow HTTP traffic (and HTTPS if you configure it):

ufw allow 80/tcp  # For HTTP
ufw allow 443/tcp # For HTTPS (if you implement it)
ufw enable        # If not already active
ufw status

Step 7: Accessing the Interface
Open a web browser and navigate to your Ubuntu server's IP address: http://<UBUNTU_SERVER_IP>/ 
You should see the OpenWrt Firewall Viewer interface.

Troubleshooting:

If the page doesn't load or you see errors, check the Apache logs:
/var/log/apache2/error.log
/var/log/apache2/php_error.log (This path might vary, often PHP errors go to error.log as well, or a specific file like /var/log/apache2/phpX.Y-fpm.log if using FPM, but the provided libapache2-mod-php suggests errors might be in Apache's main error log).

Ensure the OpenWrt router is reachable from the Ubuntu server at the specified IP.
Verify that SSH is active on the OpenWrt router and that the credentials are correct.
