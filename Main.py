import argparse
import logging
from chatbot import start_chatbot

def main():
    parser = argparse.ArgumentParser(description='Web security chatbot')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    # Set up logging
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

    # Start chatbot
    start_chatbot()

if __name__ == '__main__':
    main()
