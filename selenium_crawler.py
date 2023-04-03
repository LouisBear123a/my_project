from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def crawl_website(url, use_headless_browser=True, user_agent=None, driver=None):
    """Crawl a website and return all of its links

    Args:
        url (str): The URL of the website to crawl
        use_headless_browser (bool, optional): Whether to use a headless Chrome browser. Defaults to True.
        user_agent (str, optional): The user agent to use. Defaults to None.
        driver: A Selenium web driver instance to use. If not provided, a new one will be created.

    Returns:
        dict: A dictionary containing all of the links found on the website
    """
    if not driver:
        options = ChromeOptions()
        if use_headless_browser:
            options.add_argument('--headless')
        if user_agent:
            options.add_argument(f'user-agent={user_agent}')
        driver = Chrome(options=options)

    driver.get(url)

    # Wait for the page to load
    wait = WebDriverWait(driver, 10)
    wait.until(EC.presence_of_element_located((By.TAG_NAME, 'body')))

    # Get all links on the page
    links = driver.find_elements(By.TAG_NAME, 'a')
    links_dict = {}
    for link in links:
        href = link.get_attribute('href')
        if href:
            links_dict[href] = {}

    driver.quit()

    return links_dict
