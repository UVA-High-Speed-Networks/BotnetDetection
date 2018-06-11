##################### Libraries #####################
library(randomForest)
library(ranger)
library(plyr)
library(gbm)
library(caret)
library(pROC)

#Parallelization
library(parallel)
library(doParallel)


##################### Reading & Splitting Data #####################

all_data <- read.csv('mal_and_benign_traces.csv', header=T) #reading in the data

colnames(all_data)[20:29] <- paste("src", colnames(all_data)[20:29], sep = "_")
colnames(all_data)[30:39] <- paste("dest", colnames(all_data)[30:39], sep = "_")

all_data$Malicious <- ifelse(all_data$Malicious ==1, "Yes", "No")

set.seed(134)

train_index <- sample(1:nrow(all_data), 3000, replace= FALSE)

caret_data <- all_data[train_index,-c(2:6)]
caret_test <- all_data[-train_index,-c(2:6)]


##################### Data Exploration #####################

#First run to check variable importance
set.seed(12)
rf1 <- randomForest(all_data[,-c(1:6)], all_data[,1], mtry = 2, ntree = 300)
var_imp <- varImpPlot(rf1, sort = TRUE, main = "Variable Importance")
  

#Mean interval Distribution
boxplot(all_data[all_data[,"mean_intvl"]<40000,"mean_intvl"]~all_data[all_data[,"mean_intvl"]<40000,"Malicious"],
        notch=FALSE, 
        col=(c("darkgreen","red")),
        main="Mean Interval distribution", xlab = "Non Malicious/Malacious", ylab = "Mean Interval")

#Mean Source Packets
boxplot(all_data[all_data[,"mean_src_pkts"]<100,"mean_src_pkts"]~all_data[all_data[,"mean_src_pkts"]<100,"Malicious"],
        notch=FALSE, 
        col=(c("darkgreen","red")),
        main="Mean Source Packets Distribution", xlab = "Non Malicious/Malacious", ylab = "Mean Source Packets")
 
#Mean Duration
boxplot(all_data[all_data[,"mean_duration"],"mean_duration"]~all_data[all_data[,"mean_duration"],"Malicious"],
        notch=FALSE, 
        col=(c("darkgreen","red")),
        main="Mean Duration Distribution", xlab = "Non Malicious/Malacious", ylab = "Mean Duration")




##################### Caret Implementation of Custom Random Forest #####################

#Create custom RF function for grid search in Caret 
customRF <- list(type = "Classification", library = "randomForest", loop = NULL)
customRF$parameters <- data.frame(parameter = c("mtry", "ntree"), class = rep("numeric", 2), label = c("mtry", "ntree"))
customRF$grid <- function(x, y, len = NULL, search = "grid") {}
customRF$fit <- function(x, y, wts, param, lev, last, weights, classProbs, ...) {
  randomForest(x, y, mtry = param$mtry, ntree=param$ntree, ...)
}
customRF$predict <- function(modelFit, newdata, preProc = NULL, submodels = NULL)
  predict(modelFit, newdata)
customRF$prob <- function(modelFit, newdata, preProc = NULL, submodels = NULL)
  predict(modelFit, newdata, type = "prob")
customRF$sort <- function(x) x[order(x[,1]),]
customRF$levels <- function(x) x$classes


#Caret implementation of customRF
set.seed(3)
metric <- "ROC"
tunegrid <- expand.grid(.mtry=c(2, 6, 33), .ntree=c(100, 200, 300, 500))
rf_gridsearch <- train(as.factor(Malicious) ~., data=caret_data, method= customRF, 
                       metric="ROC", tuneGrid = tunegrid, trControl=control)
print(rf_gridsearch)
plot(rf_gridsearch)

#Create randomforest on optimum mtry and ntrees
crf <- randomForest(caret_data[,-1], as.factor(caret_data[,1]), mtry = 6, ntree = 200)

#test
test_pred_crf <- predict(crf, newdata = caret_test[,-1])
confusionMatrix(test_pred_crf, as.factor(caret_test[,1]))

##################### Custom Random Forest Results #####################
# Confusion Matrix and Statistics
# 
#              Reference
# Prediction    0    1
#            0 1056    6
#            1    2  211
# 
# Accuracy : 0.9937          
# 95% CI : (0.9877, 0.9973)
# No Information Rate : 0.8298          
# P-Value [Acc > NIR] : <2e-16          

# Sensitivity : 0.9981          
# Specificity : 0.9724          
# Pos Pred Value : 0.9944 (Correct Benign)         
# Neg Pred Value : 0.9906 (Correct Malicious)           
#F1 = 0.4962482

# Balanced Accuracy : 0.9852          