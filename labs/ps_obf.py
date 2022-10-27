'''
Class to create a standardization for the way we process data for the is_obf project.

Proper Invocation Example:
----------------------------------

from ps_obf import PS_OBF

# Create Object
# For Ryan's additional transformation
my_var = PS_OBF('../dataset/all_with_labels.csv', transform=True)

# or for no additional transformation
#my_var = PS_OBF('../dataset/all_with_labels.csv', transform=False)


# To get the new dataframe
df = my_var.data

# To get PCA dataframe that we used in the mini-lab
pca_df = my_var.pca_df

# You can also get the PCA model if you want
pca_model = my_var.pca_model

'''

import os
import pickle
#import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
# from sklearn import svm
# from sklearn.svm import SVC
# from sklearn import metrics as mt
# from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split#, GridSearchCV
# from matplotlib import pyplot as plt
# from matplotlib.colors import ListedColormap
# import warnings


class PS_OBF:
	'''Class to create a standardization for the way we process data and create models.
	When the object is created a transformation will automatically happen that creates a
	new dataframe based on standard options, additional transofrmation will happen if
	set to true, and PCA models and dataframes will be created.

	@Params:
		csv_path (str) : Locations of the csv file
		transform (bool) : True to apply ratio transformation. False to apply standard transform
	'''
	def __init__(self, csv_path, transform=False):
		self.csv_path = csv_path
		self.transform = transform
		self.original_data = None
		self.data = None # working data that is modified
		self.rd_seed = 8675309
		self.pcs = None
		self.logreg = None
		self.pca_model = None
		self.pca_df = None
		self.pca_with_label_df = None
		self.train, self.test = None, None
		self.train_features, self.test_features = None, None
		self.train_labels, self.test_labels = None, None

		# Validate CSV Path or pandas will return read as a None type
		self._validate_csv_path()

		# Generate the transformation and models
		self._load_csv()

		# If transform is set to true and we want to modify data based on ratio
		if self.transform == True:
			self.transform_on_char_ratio()

		# Generate PCA data
		self._create_pca_objects()

		'''
		# Split the data into test and training
		try:
			self._split()
		except Exception as err:
			print("An Error occured during the Train Test data split: \n{}".format(str(err)))
		'''

	def _load_csv(self):
		'''Load CSV and turn into a pandas dataframe. Always calls the _standardize()
		to remove common features that were decided not to use. Also calls the
		_split() to split the data into train/test'''
		try:
			self.original_data = pd.read_csv(self.csv_path)
			self.data = self._standardize(self.original_data)

		except Exception as err:
			print(str(err))

		# Validate data and make sure that the data is not of type None
		if str(type(self.data)) == "<class 'NoneType'>" :
			raise Exception("Data was read in as Type:None. This should not happen...")

	def _validate_csv_path(self):
		'''Make sure the csv is valid before passing it to the pandas functions'''
		if os.path.exists(self.csv_path):
			pass
		else:
			raise Exception("CSV path is not a valid location...")

	def _standardize(self, dataframe):
		'''Function that is internally called to standardize the imported data. In short this
		removes the columns vt_harmless, vt_undetected, vt_malicious, vt_suspicious,
		avclass_name, obf_name, sha1, and fpath. It also keeps only the rows that have
		the lables 1 or 3.'''
		pd_df = dataframe
		unused_columns = ['vt_harmless', 'vt_undetected', 'vt_malicious', 'vt_suspicious',
						  'avclass_name', 'obf_name', 'sha1', 'fpath']
		# Remove Duplicates
		pd_df.drop_duplicates('sha1', inplace=True)

		# Check to see if duplicate header is present. Remove if there is
		if pd_df.at[0, 'sha1'] == 'sha1':
			pd_df = pd_df.iloc[1:]

		# Remove unused columns
		pd_df = pd_df.drop(columns=unused_columns)

		# Keep only the rows that are labled 1 or 3 in the "is_obf" column
		pd_df['is_obf'] = pd.to_numeric(pd_df['is_obf'], downcast='integer')
		pd_df.drop(pd_df.loc[pd_df['is_obf']==2].index, inplace=True)

		return(pd_df)

	def split(self, data, label_name='is_obf'):
		'''Splits the data into a 80/20 test split'''
		data = data

		# Dictionary to return
		split_decision = dict()

		# Check if the 'is_obf' column exists and add it to the DF if it isn't. This is most
		# likely to happen to the PCA data
		if data.shape[1] < 5:
			data = pd.DataFrame(data, columns=['PC1', 'PC2'])
			data['is_obf'] = self.data['is_obf'].to_numpy()
			self.pca_with_label_df = data

		# Get Train and test data
		train, test = train_test_split(data, test_size=.2, random_state=self.rd_seed)
		# Subsplit for featues and lables for train and split
		train_features = train[train.columns[train.columns != label_name]].to_numpy()
		test_features = test[test.columns[test.columns != label_name]].to_numpy()
		train_labels = train[train.columns[train.columns == label_name]].to_numpy().ravel()
		test_labels = test[test.columns[test.columns == label_name]].to_numpy().ravel()

		split_decision['train'] = train
		split_decision['test'] = test
		split_decision['train_features'] = train_features
		split_decision['test_features'] = test_features
		split_decision['train_labels'] = train_labels
		split_decision['test_labels'] = test_labels

		return(split_decision)

	def transform_on_char_ratio(self):
		"""Function to turn certain features from count to percentage (ratio) values. It
		does this be deviding the feature value by the document char count. Document char count
		is also a feature within the dataset and will be ignored along with some other features.
		This transformation will help try to mitigate the affects of scaling, because as the script
		gets larger than then char count would go up too.

		Returns transformed Pandas DataFrame
		"""
		working_data = self.data  # Create DF to return
		char_count_col_name = 'doc_char_count'

		# Remove dtypes and keyword features
		ftrs_to_rmv = []
		for feat in working_data.columns.tolist():
			if 'dtype_' in feat or 'keyword_' in feat:
				if feat != 'doc_keyword_totals':
					ftrs_to_rmv.append(feat)

		working_data.drop(ftrs_to_rmv, axis=1, inplace=True)

		# List of features that would not likely be susceptible to scaling issues
		non_sus_feat_lst = ['doc_char_count', 'doc_avg_line_len', 'doc_min_line_len',
					        'doc_line_count', 'doc_mcomment_count', 'doc_entropy', 'is_obf',
							'doc_max_line_len', 'doc_keyword_totals']

		# Start looping through the working data and change the values
		for row in list(working_data.index.values):
			for col_name in working_data.columns.tolist():
				# Skip columns that we don't want to modify
				if col_name not in non_sus_feat_lst:
					working_data.at[row, col_name] = float(
						float(working_data.at[row, col_name]) / float(working_data.at[row, char_count_col_name])
						) * 100
				else:
					pass

		# Drop Char count feature since it was used as the devisor
		working_data.drop('doc_char_count', axis=1, inplace=True)

		# Drop Entropy. Only concerened with counts / sum
		working_data.drop('doc_entropy', axis=1, inplace=True)

		# Drop Line Features
		line_features = ['doc_avg_line_len', 'doc_min_line_len', 'doc_line_count', 'doc_max_line_len',
				         'doc_mcomment_count']
		working_data.drop(line_features, axis=1, inplace=True)

		self.data = working_data

	def _create_pca_objects(self):
		'''Generate the PCA model and transformed dataset from it'''
		n_comps = 2

		# Temporarly copy and drop the target column
		delta_df = self.data.copy()
		delta_df = delta_df.drop(columns=['is_obf'])

		# Create PCA object and fit it
		pca = PCA(n_components=n_comps)
		x_pca = pca.fit(delta_df).transform(delta_df)

		# Assign PCA values to class variables
		self.pca_model = pca
		self.pca_df = x_pca

	def generate_logistic_model(self):
		'''Generate a Logistic Regression model. Can be called or assigned using the
		<object>.logreg assignment.  Defaults are preset for logistic regression, but a
		list of parameters can be passed through to get different results if wanted.
		@Params:

			'''
		pass

	def export_model(self, model, write_location):
		'''Export a model to a .sav file so it can be imported later
		@Params:
			- model (PCA or Logistic) : Model object
			- write_location (string) : file path and name to write file to
		'''
		try:
			pickle.dump(model, open(write_location, 'wb'))

		except Exception as err:
			print('Could not export model: {}'.format(str(err)))

	def import_model(self, file_location):
		#TODO
		raise(NotImplementedError())

'''
if __name__ == "__main__":
	my_var = PS_OBF('../dataset/all_with_keyword_sum.csv', transform= True)

	test_train = my_var.split(my_var.data)
	pca_test_train = my_var.split(my_var.pca_df)
'''





















