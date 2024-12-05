This bot Checks whether the url is safe or not and catergorizes the url.
This checks the URL by using selenium webdrivers in headless mode and the url scan is done by the nortonsafecheck website.
It gathers all the ip address of the url domain using DIG from the terminal.
The domain IPLookup is done using the NORD api which is scraped from the website.
If you want to run the bot in the server please check the code and verify the libraries available and download them.
To get the selenium run properly is the hosting server you need to install the chrome drive seperately and run it by giving the path where the Chrome Drive file is avalilable. 

To run Dig in any server or codespace
sudo apt update
sudo apt install dnsutils -yt

To install chrome in codespace or server use
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt update
sudo apt install ./google-chrome-stable_current_amd64.deb -y
