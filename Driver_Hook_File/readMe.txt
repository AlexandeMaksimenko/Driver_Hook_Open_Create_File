TestDriver.sys
-����� ������� wrd ��������� ������ ������, �� ������� ����� �������� Hook
wrd \\.\Driver\file_name.		(����������� ����� � ������ file_name �� ���� �������, �� ����� ������������)
wrd \\.\Driver\file_name.txt		(����������� ����� � ������ file_name �� ���� �������, � ����������� .txt)
wrd \\.\Driver\C:\...\file_name.txt	(����������� ���� �� ���������� ����)
wrd \\.\Driver\??\c:\file_name.
��� ����� ������ �� �������� ���������
...
...
...
-����� ������� wrd ������� ��������� ������ ���������� ������� ����� "��������� ���������"
wrd \\.\Driver\dir_name\		(������������� ��� �������� ����� ������ ����������, �� ���� ������� � ��������� ����� ����������)
wrd \\.\Driver\C:\...\dir_name\		(������������� ��� �������� ����� ������ ����������, ������ �� ������� ���� �� ������ ����������)
...
...
...
-��� ���� ����� ���������� ������ ��������������� ������/����������
red \\.\Driver
...
��� ���� �����  ������� ������ hook'��, �� �������� �������:  wrd \\.\Driver\ddd