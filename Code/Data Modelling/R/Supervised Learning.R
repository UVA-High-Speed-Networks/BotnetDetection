##################### Libraries #####################
library(randomForest)
library(ranger)
library(plyr)
library(gbm)
library(caret)
library(pROC)
library(tidyverse)
library(plotROC)


#Parallelization
library(parallel)
library(doParallel)


##################### Reading & Splitting Data #####################

all_data <- read.csv('mal_and_benign_traces.csv', header=T) #reading in the data

colnames(all_data)[20:29] <- paste("src", colnames(all_data)[20:29], sep = "_")
colnames(all_data)[30:39] <- paste("dest", colnames(all_data)[30:39], sep = "_")

all_data$Malicious <- as.factor(ifelse(all_data$Malicious ==1, "Yes", "No"))

set.seed(134)

train_index <- sample(1:nrow(all_data), 3000, replace= FALSE)

caret_data <- all_data[train_index,-c(2:6)]
caret_test <- all_data[-train_index,-c(2:6)]


##################### Data Exploration #####################

#Mean interval Distribution
test1 <- all_data[all_data$mean_intvl<30000,]

plot1 <- ggplot(data = test1,aes(x= Malicious, y=mean_intvl, fill = Malicious)) + geom_boxplot()+
        scale_fill_manual(values=c("green", "red"))+
        theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))


#Mean Source Packets
test2 <- all_data[all_data$mean_src_pkts<100,]

ggplot(data = test2,aes(x= Malicious, y= mean_src_pkts, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))


#Mean Duration
test3 <- all_data[all_data$mean_duration<1000,]

plot2 <- ggplot(data = test3,aes(x= Malicious, y= mean_duration, fill = Malicious)) + geom_boxplot()+
  scale_fill_manual(values=c("green", "red"))+
  theme(aspect.ratio = 3/6,axis.text=element_text(size=12, face = "bold",color = "grey19"),
        axis.title=element_text(size=20,face="bold",color = "grey19"))+
  stat_summary(fun.y=mean, colour="black", geom="point", shape=18, size=3)+
  geom_text(data = test3, aes(label = Malicious, y = mean_intvl))

grid.arrange(plot1, plot2, ncol=2)

##################### Caret Implementation of Radial SVM ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(4)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


svm_Radial <- train(as.factor(Malicious) ~., data = caret_data, method = "svmRadial",
                    trControl=control,
                    preProcess = c("center"),
                    metric = "ROC",
                    tuneLength = 10)

print(svm_Radial)

# Select a parameter setting
selectedIndices_svm <- svm_Radial$pred$C == 64

g <- ggplot(svm_Radial$pred[selectedIndices_svm, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

g + annotate("text", y=0.25, x=0.75,label=paste("AUC =", round((calc_auc(g))$AUC, 4)))


#test
test_pred_svmr <- predict(svm_Radial, newdata = caret_test[,-1])
confusionMatrix(test_pred_svmr, as.factor(caret_test[,1]))

##################### SVM-R Results #####################
# Confusion Matrix and Statistics
# 
#               Reference
# Prediction    0    1
#           0 1058  207
#           1    0   10
# 
# Accuracy : 0.8376          
# 95% CI : (0.8162, 0.8575)
# Sensitivity : 1.00000         
# Specificity : 0.04608         
# Pos Pred Value : 0.83636 (Correct Benign)         
# Neg Pred Value : 1.00000  (Correct Malicious)      
#F1 = 0.4554445

#F1 AUC and ROC

#Balanced Accuracy : 0.52304 



##################### Caret Implementation of Random Forest ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(234)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


rf <- train(as.factor(Malicious) ~., data = caret_data, method = "rf",
                    trControl=control,
                    preProcess = c("center"),
                    metric = "ROC",
                    tuneLength = 10)

print(rf)

# Select a parameter setting
selectedIndices_rf <- rf$pred$mtry == 12

h <- ggplot(rf$pred[selectedIndices_rf, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

h + annotate("text", y=0.25, x=0.75,label=paste("RF AUC =", round((calc_auc(h))$AUC, 4)))


#test
test_pred_rf <- predict(rf, newdata = caret_test[,-1])
confusionMatrix(test_pred_rf, as.factor(caret_test[,1]))

##################### Random Forest Results #####################
# Confusion Matrix and Statistics
# 
# Reference
# Prediction   No  Yes
# No  1067    5
# Yes    1  202
# 
# Accuracy : 0.9953          
# 95% CI : (0.9898, 0.9983)
# No Information Rate : 0.8376          
# P-Value [Acc > NIR] : <2e-16          
# 
# Kappa : 0.9826          
# Mcnemar's Test P-Value : 0.2207          
# 
# Sensitivity : 0.9991          
# Specificity : 0.9758          
# Pos Pred Value : 0.9953          
# Neg Pred Value : 0.9951          
# Prevalence : 0.8376          
# Detection Rate : 0.8369          
# Detection Prevalence : 0.8408          
# Balanced Accuracy : 0.9875          
# 
# 'Positive' Class : No  



##################### Caret Implementation of Naive Bayes ##################### 


#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

set.seed(234)
control <- trainControl(method="cv", 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


nb <- train(as.factor(Malicious) ~., data = caret_data, method = "nb",
            trControl=control,
            preProcess = c("center"),
            metric = "ROC",
            tuneLength = 10)

print(nb)

# Select a parameter setting
selectedIndices_nb <- nb$pred$usekernel == "TRUE"

k <- ggplot(nb$pred[selectedIndices_nb, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

k + annotate("text", y=0.25, x=0.75,label=paste("AUC =", round((calc_auc(k))$AUC, 4)))


###################### Importance plots ###################

#First run to check variable importance
set.seed(12)
rf1 <- randomForest(all_data[,-c(1:6)], all_data[,1], mtry = 2, ntree = 300, importance = T)
var_imp <- varImpPlot(rf1, sort = TRUE, main = "Variable Importance")

#Asthetic changes to importance plot
imp <- data.frame((rf1$importance)[,4])

imp <- imp %>% rownames_to_column(var="Variables") %>% remove_rownames
colnames(imp)[2] <-  "MeanGiniDecrease"
imp <- imp[order(-imp$MeanGiniDecrease),][1:25,]

plot3 <- ggplot(imp) + geom_point(aes(x = MeanGiniDecrease,y = reorder(Variables, MeanGiniDecrease)), size = 5, color = "sienna2")+
  ylab("Variables") + 
  theme(panel.background = element_rect(fill = 'grey18'),
        axis.text=element_text(size=12, face = "bold",color = "grey93"),
        axis.title=element_text(size=20,face="bold",color = "grey93"),
        plot.background = element_rect(fill = "grey18"))



###################### ROC plots ###################

rf_preds <- rf$pred[selectedIndices_rf, ]
svm_preds <- svm_Radial$pred[selectedIndices_svm, ]
nb_preds <- nb$pred[selectedIndices_nb, ]

#Select only relevant columns
rf_no_preds <- rf_preds[, c(2,4,5)]
svm_no_preds <- svm_preds[, c(2,4,5)]
nb_no_preds <- nb_preds[, c(2,4,5)]

#Rename probablilites column to identify model
colnames(rf_no_preds)[2] <- "Random Forest"
colnames(svm_no_preds)[2] <- "Radial SVM"
colnames(nb_no_preds)[2] <- "Naive Bayes"


#Merge probabilities
all_preds <- Reduce(function(dtf1, dtf2) merge(dtf1, dtf2, by = c("obs", "rowIndex"), all = TRUE),list(rf_no_preds,svm_no_preds, nb_no_preds))


#Melt into longform for vizualization
longtest <- melt_roc(all_preds, "obs", c("Random Forest", "Radial SVM", "Naive Bayes"))
  

#Plot
combined_roc <- ggplot(longtest, aes(d = D, m = M, color = name )) + geom_roc(n.cuts = F, size = 3)
  
plot4 <- combined_roc+ annotate("text", y=0.28, x=0.74,color = "grey93",size = 8,label=paste("RF AUC =",round((calc_auc(h))$AUC, 4)))+
              annotate("text", y=0.23, x=0.74,color = "grey93",size = 8,label=paste("SVM AUC =", round((calc_auc(g))$AUC, 4)))+
              annotate("text", y=0.18, x=0.74,color = "grey93",size = 8,label=paste("NB AUC =", round((calc_auc(k))$AUC, 4)))+
              theme(panel.background = element_rect(fill = 'grey18'),
              axis.text=element_text(size=12, face = "bold",color = "grey93"),
              axis.title=element_text(size=20,face="bold",color = "grey93"),
              plot.background = element_rect(fill = "grey18"))

grid.arrange(plot1, plot2, ncol=2)
