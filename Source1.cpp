#include <string>
#include <stdio.h>
#include <vector>
#include <string.h>
//#include <iostream>
#include <algorithm>
#include "windows.h"
#include <map>
#include <unordered_map>
#include <stack>
#include <queue>

using namespace std;

typedef std::string uint8_t;



struct TreeNode
{
	uint8_t val;
	int count ;
	TreeNode* child;
	vector<TreeNode*> sibling;
	TreeNode(uint8_t x) : val(x), child(NULL) {}
};

void Insert(TreeNode* root,uint8_t value)
{
	TreeNode * temproot = new TreeNode(value);
	if (root->child == NULL)
		root->child = temproot;
	else
		root->sibling.push_back(temproot);
}

int countNode(TreeNode* root, int num)
{
	if (root == nullptr)
		return 1;
	num = countNode(root->child, num);
	for (size_t i = 0; i < root->sibling.size(); i++)
		num += countNode(root->sibling[i], num);

	root->count = num;
	return num;
}

void Create(TreeNode* root,vector<vector<uint8_t>> test)
{
	for (size_t i = 0; i < test.size(); i++)
	{
		TreeNode* cur = root;
		for (size_t j = 0; j < test[0].size(); j++)
		{
			if (cur->child != nullptr&&cur->child->val == test[i][j])
			{
				cur = cur->child;
				continue;
			}
			else if (cur->sibling.size()>0)
			{
				int k = 0;
				int size = cur->sibling.size();
				while (k < size)
				{
					if (cur->sibling[k]->val == test[i][j])
					{
						cur = cur->sibling[k];
						break;
					}
					k++;
				}
				if (k < size)
					continue;
			}
			Insert(cur, test[i][j]);
			if (cur->sibling.size() == 0)
				cur = cur->child;
			else
				cur = cur->sibling.back();
		}
	}
	countNode(root, 0);
}



void BFS(TreeNode* root, uint8_t value)
{
	queue<TreeNode*> treeQ;
	TreeNode* roottemp;
	TreeNode* curr=nullptr;
	if (root == nullptr)
		return;
	treeQ.push(root);
	while (!treeQ.empty())
	{
		int size = treeQ.size();
		int i = 0;
		while (i < size)
		{
			roottemp = treeQ.front();
			treeQ.pop();
			if (roottemp->child != nullptr)
			{
				if (roottemp->child->val == value)
				{
					curr = roottemp->child;
					break;
				}
				else
					treeQ.push(roottemp->child);
				if (roottemp->sibling.size()>0)
				{
					for (size_t j = 0; j < roottemp->sibling.size(); j++)
					{
						if (roottemp->sibling[j]->val == value)
						{
							curr = roottemp->sibling[j];
							break;
						}
						else
							treeQ.push(roottemp->sibling[j]);
					}
				}
			}
			i++;
		}
		if (curr != nullptr)
			break;
	}
}

int main()
{
	vector<vector<uint8_t>> test ;
	vector<uint8_t> subtest;
	TreeNode* root = new TreeNode("0");
	uint8_t query = "2";

	for(int i=0;i<3;i++)
	{
		subtest.clear();
		for(int j=1;j<3;j++)
			subtest.push_back(to_string(j));
		test.push_back(subtest);
	}

	Create(root, test);

	BFS(root,query);

	system("pause");
}