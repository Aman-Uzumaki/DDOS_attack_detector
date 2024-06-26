# !pip install liac-arff

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
import arff as arf

file = open("final-dataset.arff")
decoder = arf.ArffDecoder()
data = decoder.decode(file,encode_nominal=True)
# data = arf.load(file)
# file.close()
# relation = data['relation']
# attributes = data['attributes']
# instances = data['data']

# import os

# file_path = "final-dataset.arff"
# if os.path.exists(file_path):
#     file = open(file_path, 'r')
#     data = arf.load(file)
#     file.close()
#     if isinstance(data, dict):
#         relation = data.get('relation')
#         attributes = data.get('attributes')
#         instances = data.get('data')
#         if relation and attributes and instances:
#             print("Data loaded successfully.")
#         else:
#             print("Data loaded, but missing required keys.")
#     else:
#         print("Data is not a dictionary.")
# else:
#     print("File does not exist.")

vals = [val[0:-1] for val in data['data']]
labels = [lab[-1] for lab in data['data']]

da = set(labels)
brac = 600
templ = []
tempd = []
for i in da:
  coun = 0
  while coun < brac:
    for j in range(len(labels)):
      if labels[j]:
        templ.append(labels[j])
        tempd.append(vals[j])
        coun += 1
      if coun == brac:
        break
vals = tempd
labels = templ

l = len(vals)
print(l)

X_train,X_test,Y_train,Y_test = train_test_split(vals,labels,stratify = labels,test_size=0.2,random_state=0)

scaler = StandardScaler()
x_train = scaler.fit_transform(X_train)
x_test = scaler.transform(X_test)
y_train = np.array(Y_train)
y_test = np.array(Y_test)

model = SVC(kernel = 'sigmoid', gamma = 'auto')
model.fit(x_train, y_train)

y_pred = model.predict(x_test)

print((accuracy_score(y_pred,y_test))*100,"%")

model1 = KNeighborsClassifier(n_neighbors=5)
model1.fit(x_train,y_train)

y_pred1 = model1.predict(x_test)

print(accuracy_score(y_pred1,y_test)*100,"%")

model2 = GaussianNB()
model2.fit(x_train, y_train)

y_pred2 = model2.predict(x_test)

print((accuracy_score(y_pred2, y_test))*100,"%")

train_x, val_x, train_y, val_y = train_test_split(x_train,y_train,stratify = y_train, test_size = 0.2,random_state=0)

print(x_train.shape, x_test.shape)

columns = ['SRC_ADD','DES_ADD','PKT_ID','FROM_NODE','TO_NODE','PKT_TYPE',
           'PKT_SIZE','FLAGS','FID','SEQ_NUMBER','NUMBER_OF_PKT',
           'NUMBER_OF_BYTE','NODE_NAME_FROM','NODE_NAME_TO','PKT_IN','PKT_OUT',
           'PKT_R','PKT_DELAY_NODE','PKT_RATE','BYTE_RATE','PKT_AVG_SIZE',
           'UTILIZATION','PKT_DELAY','PKT_SEND_TIME','PKT_RESEVED_TIME',
           'FIRST_PKT_SENT','LAST_PKT_RESEVED']

model1 = SVC(kernel = 'sigmoid',gamma='auto')
model1.fit(train_x,train_y)
y_val_pred1 = model1.predict(val_x)
y_val_pred1 = pd.DataFrame(y_val_pred1)
y_test_pred1 = model1.predict(x_test)
y_test_pred1 = pd.DataFrame(y_test_pred1)

model2 = KNeighborsClassifier(n_neighbors = 5)
model2.fit(train_x,train_y)
y_val_pred2 = model2.predict(val_x)
y_val_pred2 = pd.DataFrame(y_val_pred2)
y_test_pred2 = model2.predict(x_test)
y_test_pred2 = pd.DataFrame(y_test_pred2)

model3 = GaussianNB()
model3.fit(train_x,train_y)
y_val_pred3 = model3.predict(val_x)
y_val_pred3 = pd.DataFrame(y_val_pred3)
y_test_pred3 = model3.predict(x_test)
y_test_pred3 = pd.DataFrame(y_test_pred3)

val_input = pd.concat([pd.DataFrame(val_x,columns=columns),y_val_pred1,y_val_pred2,y_val_pred3],axis=1)
test_input = pd.concat([pd.DataFrame(x_test,columns=columns),y_test_pred1,y_test_pred2,y_test_pred3],axis=1)

val_input.columns = val_input.columns.astype(str)
test_input.columns = test_input.columns.astype(str)

model = RandomForestClassifier(n_estimators=200)
model.fit(val_input,val_y)

print((model.score(test_input,y_test))*100,"%")

import joblib

# Save models
joblib.dump(model1, 'svm_model.pkl')
joblib.dump(model2, 'knn_model.pkl')
joblib.dump(model3, 'gnb_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(model, 'random_forest_ensemble_model.pkl')
