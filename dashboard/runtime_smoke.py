import os

from playwright.sync_api import sync_playwright


def main():
    assert os.getuid() == 10001, f'expected UID 10001, got {os.getuid()}'
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(args=['--disable-dev-shm-usage'])
        try:
            page = browser.new_page()
            page.set_content('<title>sandbox-ok</title>')
            assert page.title() == 'sandbox-ok'
        finally:
            browser.close()


if __name__ == '__main__':
    main()
