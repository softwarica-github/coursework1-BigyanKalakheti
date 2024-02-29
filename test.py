import unittest
from unittest.mock import patch, mock_open , MagicMock
from sqlicli import (
    has_parameters,
    perform_request,
    try_login,
    exploit_sqli_column_number,
    generate_sql_payload,
    save_to_file,
    main
)

class TestSQLiCli(unittest.TestCase):

    @patch('requests.get')
    def test_has_parameters_with_parameters(self, mock_get):
        mock_get.return_value.status_code = 200
        self.assertTrue(has_parameters('http://example.com/?param=value'))

    def test_has_parameters_without_parameters(self):
        self.assertFalse(has_parameters('http://example.com/'))

    @patch('requests.get')
    def test_perform_request_get(self, mock_get):
        mock_get.return_value.status_code = 200
        self.assertEqual(perform_request('http://example.com/', 'payload', 'GET').status_code, 200)

    @patch('requests.post')
    def test_perform_request_post(self, mock_post):
        mock_post.return_value.status_code = 200
        self.assertEqual(perform_request('http://example.com/', 'payload', 'POST', {'data': 'value'}).status_code, 200)

    @patch('requests.get')
    def test_try_login_successful(self, mock_get):
        mock_get.return_value.text = '<input value="csrf_token">'
        mock_get.return_value.status_code = 200
        with patch('sqlicli.perform_request', return_value=MagicMock(status_code=200)):
            self.assertTrue(try_login('http://example.com/', 'GET', {'username': 'user', 'password': 'pass'}))

    @patch('requests.get')
    def test_try_login_unsuccessful(self, mock_get):
        mock_get.return_value.text = '<input value="csrf_token">'
        mock_get.return_value.status_code = 200
        with patch('sqlicli.perform_request', return_value=MagicMock(status_code=401)):
            self.assertFalse(try_login('http://example.com/', 'GET', {'username': 'user', 'password': 'pass'}))


    @patch('requests.get')
    def test_exploit_sqli_column_number(self, mock_get):
        mock_get.return_value.status_code = 500
        self.assertEqual(exploit_sqli_column_number('http://example.com/', 'GET'), 'one column')

    # Add more test cases for other functions
    def test_generate_sql_payload(self):
        self.assertEqual(
            generate_sql_payload(3, 2, 'table_name'),"' UNION SELECT NULL, table_name, NULL FROM information_schema.tables--"
           
        )
    

    def test_save_to_file(self):
        with patch('builtins.input', return_value='test_file.txt'), patch('builtins.open', mock_open()) as m:
            save_to_file('test_content')
            m.assert_called_once_with('test_file.txt', 'w')
            m().write.assert_called_once_with('test_content')

if __name__ == '__main__':
    unittest.main()
