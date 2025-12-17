import streamlit as st
import pickle
import numpy as np

# Load the trained model
with open('model.pkl','rb') as file:
    model = pickle.load(file)

# App title
st.title("🩺 Logistic Regression Diabetes Prediction App")

# Input fields
st.header("Enter Input Features:")
Pregnancies = st.number_input("Pregnancies", min_value=0.0)
Glucose = st.number_input("Glucose", min_value=0.0)
BloodPressure = st.number_input("BloodPressure", min_value=0.0)
SkinThickness = st.number_input("SkinThickness", min_value=0.0)
Insulin = st.number_input("Insulin", min_value=0.0)
BMI = st.number_input("BMI", min_value=0.0)
DiabetesPedigreeFunction = st.number_input("DiabetesPedigreeFunction", min_value=0.0)
Age = st.number_input("Age", min_value=0.0)

# Prediction button
if st.button("Predict"):
    # Prepare input data for prediction
    input_data = np.array([[Pregnancies, Glucose, BloodPressure, SkinThickness, Insulin, BMI, DiabetesPedigreeFunction, Age]])
    
    # Make prediction
    prediction = model.predict(input_data)
    
    # Show result
    st.success(f"Predicted Output: {int(prediction[0])}")
    
    if prediction[0] == 1:
        st.error("The person is **diabetic**")
    else:
        st.success("The person is **not diabetic**")











