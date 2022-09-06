# -*- coding: utf-8 -*-
"""
Created on Sun Sep  4 18:43:41 2022
@author: Abillelatus (Ryan Herrin)

Code for testing and modeling Powershell Obscuration classification using a provided 
data set with predetermined features. 

PCA may be the preferred method for the unsupervised approach as the data provided is 
not labled. 

Current Models do not include the "sha1" and "fpath" columns
"""

import sys
import pandas as pd
#import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import seaborn as sns; sns.set(style='white')


# Define Global
original_data_path = "../dataset/all.csv" # this file is originally zipped
# Some columns are empty for future use. Set to False to not include them
include_unused_columns = False 

# Give option to scale the data if wanted
scale_data = False

# Define unused columns here
unused_columns = ['vt_harmless', 'vt_undetected', 'vt_malicious', 'vt_suspicious',
				  'avclass_name', 'is_obf', 'obf_name']

# Remove the string columns sha1 and fpath
include_sha1_fpath = False
if include_sha1_fpath == False:
	unused_columns.append('sha1')
	unused_columns.append('fpath')
	
def create_workable_data(file_path, lst_unused_columns):
	'''import the dataset and format the data into a pandas dataframe.
	+ Read in CSV as dataframe
	+ Remove extra header if there is one 
	+ Remove unused columns if set 
	+ Typecast DataTypes to string and integers
	+ Returns Pandas DataFrame object'''
	try:
		pd_df = pd.read_csv(file_path) # Read in CSV as dataframe
	except FileNotFoundError():
		print("Could not find data file. Make sure the file is unzipped...")
		sys.exit(1)
		
	# Remove Duplicates
	pd_df.drop_duplicates('sha1', inplace=True)
		
	# Check to see if duplicate header is present. Remove if there is 
	if pd_df.at[0, 'sha1'] == 'sha1':
		pd_df = pd_df.iloc[1:] # .iloc[] integer-loc based indexing for selecting by position 
		
	# Remove unused columns if global var "include_unused_columns" is set to False
	if include_unused_columns == False:
		pd_df = pd_df.drop(columns=lst_unused_columns)
		
	# Convert data types to best type of datatypes
	pd_df = pd_df.convert_dtypes()
	
	return(pd_df)

# Create a Data Frame from the csv 
data_df = create_workable_data(original_data_path, unused_columns)

def data_scale(data_set):
	'''Return dataframe that has been scaled using standardization''' 
	col_names = data_set.columns.tolist() # Grab column names
	std_scaler = StandardScaler() # Scaler object
	df_scaled = std_scaler.fit_transform(data_set.to_numpy())
	# transform numpy array back to pandas dataframe 
	df_scaled = pd.DataFrame(df_scaled, columns=col_names)
	
	return(df_scaled)

# scale scale_data if set to True
if scale_data:
	data_df = data_scale(data_df)
	
# Create function to identify the best number of components
def find_opt_n_components(data_set):
	'''Find the number of components that can explain the most data.'''
	set_percentage = .98 # Percentage of data explained

	# The range is the number of components to test
	for comp in range(2, data_set.shape[1]):
		pca = PCA(n_components = comp, random_state=42)
		pca.fit(data_set)
		comp_check = pca.explained_variance_ratio_
		final_comp = comp
		
		if comp_check.sum() >= set_percentage:
			break

	return(final_comp)

### Notes ###
"""
Running the find_opt_n_components varies depending if the data has been scaled
or not. To reach 95% of data explained the non-scaled data only needs 3 n_components
as compared to 49 for the scaled data.
"""

# Get n_comp number
n_comp = find_opt_n_components(data_df)

# PCA Analysis
final_pca = PCA(n_components=n_comp)
x_pca = final_pca.fit(data_df).transform(data_df)

# Create 3D visualization and see how much variation the x_pca dataset
# actually accounts for. 
if scale_data == False:
	print("\nExplained variation per principal component: {}\n".format(
		final_pca.explained_variance_ratio_))
else:
	#TODO: Create function for scaled data
	pass

# Create a function to format weights to readable strings 
def get_feat_names_from_weights(weights, names):
    tmp_array = []
    for comp in weights:
        tmp_string = ''
        for fidx,f in enumerate(names):
            if fidx>0 and comp[fidx]>=0:
                tmp_string+='+'
            tmp_string += '%.2f*%s ' % (comp[fidx],f[:-5])
        tmp_array.append(tmp_string)
		
    return(tmp_array)

# Create readable weights per feature 
pca_weight_strings = get_feat_names_from_weights(final_pca.components_,
												 data_df.columns.tolist())

# Create Dataframes from the transformed outputs
pca_df = pd.DataFrame(x_pca, columns=[pca_weight_strings])

"""
# Try and plot/display the data
data_plot = pca_df.plot.scatter(pca_weight_strings[0], pca_weight_strings[1],
								pca_weight_strings[2], c='DarkBlue')
newfig = plt.figure()
plt.show()
"""
















