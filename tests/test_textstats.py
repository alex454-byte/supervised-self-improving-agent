"""Tests for the toy domain."""
import unittest

from agentlib.textstats import word_count, words


class TextStatsTests(unittest.TestCase):
    def test_words_ignore_punctuation_and_digits(self):
        self.assertEqual(words("It's 3 o'clock, isn't it?"), ["It's", "o'clock", "isn't", "it"])

    def test_word_count(self):
        self.assertEqual(word_count(""), 0)
        self.assertEqual(word_count("one two  three"), 3)


if __name__ == "__main__":
    unittest.main()
